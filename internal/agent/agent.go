// Package agent keeps the configured DNS records in sync with Cloudflare.
//
// Every round resolves the zone and the record again, so a lookup that failed
// (for example because the WAN was down when the container started) never
// sticks: the next round repeats it. Zone IDs are cached between rounds and
// dropped as soon as a call using them fails.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/cloudflare"
	"github.com/notolac/ozgo-cf-ddns/internal/config"
	"github.com/notolac/ozgo-cf-ddns/internal/ipdetect"
)

// PublicDetector finds the public IP address of the host.
type PublicDetector interface {
	Detect(ctx context.Context, v6 bool, dnsServer string) (netip.Addr, string, error)
}

// Options configure an Agent. Zero fields get production defaults.
type Options struct {
	Version     string
	Logger      *slog.Logger
	Cloudflare  *cloudflare.Client
	Public      PublicDetector
	Now         func() time.Time
	RecordLimit time.Duration // timeout for one record; default 60 s
	MaxBackoff  time.Duration // cap of the retry delay after failures; default 5 min
	BaseBackoff time.Duration // first retry delay after a failed round; default 30 s
}

// Agent runs the sync loop.
type Agent struct {
	cfg    *config.Config
	opt    Options
	log    *slog.Logger
	status *Status
	zones  map[zoneKey]string // only used by the loop goroutine
}

type zoneKey struct {
	auth cloudflare.Auth
	zone string
}

// New creates an agent.
func New(cfg *config.Config, opt Options) *Agent {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Cloudflare == nil {
		opt.Cloudflare = &cloudflare.Client{}
	}
	if opt.Cloudflare.UserAgent == "" {
		opt.Cloudflare.UserAgent = "ozgo-cf-ddns/" + opt.Version
	}
	if opt.Public == nil {
		opt.Public = &ipdetect.Public{}
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.RecordLimit == 0 {
		opt.RecordLimit = 60 * time.Second
	}
	if opt.BaseBackoff == 0 {
		opt.BaseBackoff = 30 * time.Second
	}
	if opt.MaxBackoff == 0 {
		opt.MaxBackoff = 5 * time.Minute
	}
	return &Agent{
		cfg:    cfg,
		opt:    opt,
		log:    opt.Logger,
		status: newStatus(opt.Version, opt.Now(), cfg),
		zones:  map[zoneKey]string{},
	}
}

// Status returns the shared status for the web interface.
func (a *Agent) Status() *Status { return a.status }

// Run syncs immediately, then on every CRON activation. After a failed round
// it retries sooner, with exponential backoff capped at MaxBackoff. On
// cancellation it removes the records marked DELETE_ON_STOP and returns.
func (a *Agent) Run(ctx context.Context) {
	failedRounds := 0
	for {
		failed := a.Round(ctx)
		if ctx.Err() != nil {
			break
		}
		now := a.opt.Now()
		next := a.cfg.Schedule.Next(now)
		if failed > 0 {
			failedRounds++
			if retry := now.Add(a.backoff(failedRounds)); next.IsZero() || retry.Before(next) {
				next = retry
			}
		} else {
			failedRounds = 0
		}
		a.status.round(time.Time{}, time.Time{}, next)
		a.log.Debug("next round scheduled", "at", next.Format(time.RFC3339))

		timer := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			break
		}
	}
	a.cleanup()
}

func (a *Agent) backoff(n int) time.Duration {
	d := a.opt.BaseBackoff
	for i := 1; i < n && d < a.opt.MaxBackoff; i++ {
		d *= 2
	}
	return min(d, a.opt.MaxBackoff)
}

type ipKey struct {
	v6  bool
	dns string
}

type ipResult struct {
	addr   netip.Addr
	method string
	err    error
}

// Round syncs every record once and returns the number of failures.
func (a *Agent) Round(ctx context.Context) int {
	start := a.opt.Now()
	a.status.round(start, time.Time{}, time.Time{})
	public := map[ipKey]ipResult{} // detect the public IP once per round
	var ok, changed, failed int
	for i, r := range a.cfg.Records {
		if ctx.Err() != nil {
			break
		}
		upd, err := a.syncRecord(ctx, i, r, public)
		switch {
		case err != nil:
			failed++
		case upd:
			changed++
			ok++
		default:
			ok++
		}
	}
	end := a.opt.Now()
	a.status.round(time.Time{}, end, time.Time{})
	lvl := slog.LevelInfo
	if failed > 0 {
		lvl = slog.LevelWarn
	}
	a.log.Log(ctx, lvl, "round finished",
		"records", len(a.cfg.Records), "ok", ok, "updated", changed, "failed", failed,
		"duration", end.Sub(start).Round(time.Millisecond).String())
	return failed
}

func (a *Agent) desiredIP(ctx context.Context, r config.Record, public map[ipKey]ipResult) (netip.Addr, error) {
	switch r.Source {
	case config.SourceStatic:
		return r.StaticIP, nil
	case config.SourceCommand:
		return ipdetect.Command(ctx, r.LookupCmd, r.IPv6())
	case config.SourceInterface:
		return ipdetect.Interface(r.Interface, r.IPv6())
	}
	k := ipKey{v6: r.IPv6(), dns: r.DNSServer}
	res, ok := public[k]
	if !ok {
		res.addr, res.method, res.err = a.opt.Public.Detect(ctx, k.v6, k.dns)
		public[k] = res
		if res.err == nil {
			a.log.Debug("public IP detected", "ip", res.addr.String(), "method", res.method)
		}
	}
	if res.err != nil {
		return netip.Addr{}, fmt.Errorf("public IP detection failed: %w", res.err)
	}
	return res.addr, nil
}

func (a *Agent) zoneID(ctx context.Context, auth cloudflare.Auth, zone string) (string, error) {
	k := zoneKey{auth, zone}
	if id, ok := a.zones[k]; ok {
		return id, nil
	}
	id, err := a.opt.Cloudflare.ZoneID(ctx, auth, zone)
	if err != nil {
		return "", err
	}
	a.zones[k] = id
	return id, nil
}

func authOf(r config.Record) cloudflare.Auth {
	return cloudflare.Auth{Token: r.Credentials.Token, Email: r.Credentials.Email}
}

// syncRecord reconciles one record. It reports whether Cloudflare was changed.
func (a *Agent) syncRecord(ctx context.Context, i int, r config.Record, public map[ipKey]ipResult) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, a.opt.RecordLimit)
	defer cancel()
	log := a.log.With("record", r.FQDN(), "type", r.Type)
	now := a.opt.Now()

	fail := func(err error) (bool, error) {
		prev := a.status.Snapshot().Records[i]
		a.status.update(i, func(s *RecordStatus) {
			s.State, s.LastCheck = StateError, now
			s.LastError, s.LastErrorAt = err.Error(), now
			s.Failures++
		})
		log.Warn("sync failed", "error", err.Error(), "consecutive_failures", prev.Failures+1)
		return false, err
	}

	ip, err := a.desiredIP(ctx, r, public)
	if err != nil {
		return fail(err)
	}
	auth := authOf(r)
	zoneID, err := a.zoneID(ctx, auth, r.Zone)
	if err != nil {
		return fail(fmt.Errorf("zone lookup: %w", err))
	}
	recs, err := a.opt.Cloudflare.ListRecords(ctx, auth, zoneID, r.Type, r.FQDN())
	if err != nil {
		delete(a.zones, zoneKey{auth, r.Zone}) // the cached zone ID may be stale
		return fail(fmt.Errorf("record lookup: %w", err))
	}

	var cur cloudflare.DNSRecord
	changed := false
	switch {
	case len(recs) == 0:
		cur, err = a.opt.Cloudflare.CreateRecord(ctx, auth, zoneID, cloudflare.DNSRecord{
			Type: r.Type, Name: r.FQDN(), Content: ip.String(), Proxied: r.Proxied,
		})
		if err != nil {
			return fail(fmt.Errorf("create record: %w", err))
		}
		changed = true
		log.Info("record created", "ip", ip.String(), "proxied", r.Proxied)
	default:
		cur = recs[0]
		if len(recs) > 1 {
			log.Warn("several records share this name and type; only the first is managed", "count", len(recs))
		}
		curIP, perr := netip.ParseAddr(cur.Content)
		if perr == nil && curIP.Unmap() == ip && cur.Proxied == r.Proxied {
			log.Debug("record in sync", "ip", ip.String(), "proxied", r.Proxied)
			break
		}
		old, oldProxied := cur.Content, cur.Proxied
		cur, err = a.opt.Cloudflare.UpdateRecord(ctx, auth, zoneID, recs[0].ID, ip.String(), r.Proxied)
		if err != nil {
			return fail(fmt.Errorf("update record: %w", err))
		}
		changed = true
		log.Info("record updated", "old_ip", old, "ip", ip.String(), "old_proxied", oldProxied, "proxied", r.Proxied)
	}

	prev := a.status.Snapshot().Records[i]
	if prev.State == StateError {
		log.Info("record recovered", "after_failures", prev.Failures)
	}
	proxied := cur.Proxied
	a.status.update(i, func(s *RecordStatus) {
		s.State, s.LastCheck, s.LastSuccess = StateOK, now, now
		s.DesiredIP, s.CloudflareIP = ip.String(), cur.Content
		s.CloudflareProxied, s.CloudflareModified = &proxied, cur.ModifiedOn
		s.Failures = 0
		if changed {
			s.LastChange = now
		}
	})
	return changed, nil
}

// cleanup deletes the records marked DELETE_ON_STOP.
func (a *Agent) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, r := range a.cfg.Records {
		if !r.DeleteOnStop {
			continue
		}
		log := a.log.With("record", r.FQDN(), "type", r.Type)
		if err := a.deleteRecord(ctx, r); err != nil {
			log.Error("delete on stop failed", "error", err.Error())
			continue
		}
		log.Info("record deleted on stop")
	}
}

func (a *Agent) deleteRecord(ctx context.Context, r config.Record) error {
	auth := authOf(r)
	zoneID, err := a.zoneID(ctx, auth, r.Zone)
	if err != nil {
		return err
	}
	recs, err := a.opt.Cloudflare.ListRecords(ctx, auth, zoneID, r.Type, r.FQDN())
	if err != nil {
		return err
	}
	var errs []error
	for _, rec := range recs {
		errs = append(errs, a.opt.Cloudflare.DeleteRecord(ctx, auth, zoneID, rec.ID))
	}
	return errors.Join(errs...)
}
