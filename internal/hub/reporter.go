package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/agent"
)

// Source provides the status a sidecar reports.
type Source interface {
	Snapshot() agent.Snapshot
}

// Reporter sends the status of a sidecar to the main container.
//
// Reporting never affects DNS updates or the health of the sidecar. A failed
// report is simply sent again at the next interval or round.
type Reporter struct {
	URL      string // base URL of the main container
	Key      []byte
	Instance string
	Source   Source
	Client   *http.Client
	Logger   *slog.Logger
	Interval time.Duration // heartbeat; default 30 s
	Now      func() time.Time

	lastTS   int64
	failures int
}

// Run reports at once, then after every signal on changes and every Interval,
// until ctx is cancelled.
func (r *Reporter) Run(ctx context.Context, changes <-chan struct{}) {
	if r.Interval == 0 {
		r.Interval = 30 * time.Second
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		r.report(ctx)
		select {
		case <-ctx.Done():
			return
		case <-changes:
		case <-t.C:
		}
	}
}

func (r *Reporter) report(ctx context.Context) {
	err := r.Send(ctx)
	if ctx.Err() != nil {
		return
	}
	log := r.logger()
	switch {
	case err == nil && r.failures > 0:
		log.Info("reporting to the main container restored", "url", r.URL, "after_failures", r.failures)
		r.failures = 0
	case err == nil:
		log.Debug("status reported", "url", r.URL)
	default:
		r.failures++
		// Warn on the first failure and then every 10th, to keep the log readable.
		if r.failures == 1 || r.failures%10 == 0 {
			log.Warn("cannot report to the main container", "url", r.URL, "error", err.Error(),
				"consecutive_failures", r.failures)
		} else {
			log.Debug("cannot report to the main container", "error", err.Error(), "consecutive_failures", r.failures)
		}
	}
}

func (r *Reporter) logger() *slog.Logger {
	if r.Logger == nil {
		return slog.Default()
	}
	return r.Logger
}

// Send posts one signed report.
func (r *Reporter) Send(ctx context.Context) error {
	body, err := json.Marshal(Report{Instance: r.Instance, Status: r.Source.Snapshot()})
	if err != nil {
		return err
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	ts := now().UnixMilli()
	if ts <= r.lastTS {
		ts = r.lastTS + 1 // keep timestamps strictly increasing
	}
	r.lastTS = ts

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL+Path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, Sign(r.Key, ts, body))

	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req) // #nosec G704 -- SYNC_URL is operator configuration, validated in config
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("main container answered %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}
