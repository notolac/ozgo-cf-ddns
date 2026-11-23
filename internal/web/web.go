// Package web serves the read-only status interface.
//
//	GET /             HTML status page (refreshes every 30 s)
//	GET /api/status   the same data as JSON
//	GET /healthz      200 when every record is in sync, 503 otherwise
//	POST /api/sync    signed status reports from sidecars (main container only)
//
// When a user and password are configured, / and /api/status require HTTP
// basic auth. /healthz stays open for the container health check and only
// returns counts, never record names. /api/sync has its own authentication:
// every report is signed with SYNC_KEY (see package hub).
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/agent"
	"github.com/notolac/ozgo-cf-ddns/internal/hub"
)

//go:embed templates/index.html
var files embed.FS

// Source provides the state to display.
type Source interface {
	Snapshot() agent.Snapshot
}

// Remotes provides the sidecars that report to this container.
type Remotes interface {
	Remotes() []hub.Remote
}

// Options configure the handler.
type Options struct {
	User     string
	Password string
	Logger   *slog.Logger
	Now      func() time.Time
	Instance string       // name of this container; shown when sidecars report
	Remotes  Remotes      // sidecars; nil when this is not a main container
	Sync     http.Handler // POST /api/sync; nil when this is not a main container
}

type server struct {
	src  Source
	opt  Options
	page *template.Template
}

// Handler returns the HTTP handler for the status interface.
func Handler(src Source, opt Options) http.Handler {
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	s := &server{src: src, opt: opt}
	s.page = template.Must(template.New("index.html").Funcs(template.FuncMap{
		"ts":  s.formatTime,
		"ago": s.ago,
		"deref": func(b *bool) bool {
			return b != nil && *b
		},
	}).ParseFS(files, "templates/index.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /api/status", s.auth(http.HandlerFunc(s.api)))
	mux.Handle("GET /{$}", s.auth(http.HandlerFunc(s.index)))
	if opt.Sync != nil {
		mux.Handle("POST "+hub.Path, opt.Sync)
	}
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *server) auth(next http.Handler) http.Handler {
	if s.opt.User == "" {
		return next
	}
	// SHA-256 is not used to store or protect the password: both sides are
	// hashed in memory only so subtle.ConstantTimeCompare sees equal-length
	// inputs and the comparison does not leak the length of the secret.
	// (CodeQL go/weak-sensitive-data-hashing: false positive, dismissed.)
	wantUser := sha256.Sum256([]byte(s.opt.User))
	wantPass := sha256.Sum256([]byte(s.opt.Password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		gotUser := sha256.Sum256([]byte(u))
		gotPass := sha256.Sum256([]byte(p))
		userOK := subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) == 1
		passOK := subtle.ConstantTimeCompare(gotPass[:], wantPass[:]) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="ozgo-cf-ddns", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	snap := s.src.Snapshot()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	switch {
	case snap.Healthy:
		fmt.Fprintf(w, "ok: %d records in sync\n", snap.OK)
	case snap.RoundEnd.IsZero():
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "starting: first round not finished")
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "unhealthy: %d ok, %d failing, %d pending\n", snap.OK, snap.Errors, snap.Pending)
	}
}

// apiStatus keeps the v0.1 layout (the local snapshot at the top level) and
// adds the sidecars.
type apiStatus struct {
	agent.Snapshot
	Instance string       `json:"instance,omitempty"`
	Sidecars []hub.Remote `json:"sidecars,omitempty"`
}

func (s *server) remotes() []hub.Remote {
	if s.opt.Remotes == nil {
		return nil
	}
	return s.opt.Remotes.Remotes()
}

func (s *server) api(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	out := apiStatus{Snapshot: s.src.Snapshot(), Instance: s.opt.Instance, Sidecars: s.remotes()}
	if err := enc.Encode(out); err != nil {
		s.opt.Logger.Debug("writing status JSON", "error", err.Error())
	}
}

// zoneView groups the records of one zone (the main domain they belong to).
type zoneView struct {
	Zone                string
	OK, Errors, Pending int
	Records             []recordView
}

// recordView adds the host part of the name, shown in front of the zone.
type recordView struct {
	agent.RecordStatus
	Host string // "@" for the zone apex
}

// instanceView is one container: this one or a sidecar.
type instanceView struct {
	agent.Snapshot
	Name       string
	Local      bool
	Stale      bool
	LastReport time.Time
	Zones      []zoneView
}

type pageView struct {
	Local     instanceView
	Instances []instanceView // the local container first, then sidecars by name
	Multi     bool           // show one section per container
	Healthy   bool
	OK        int
	Errors    int
	Pending   int
	Stale     int
	Zones     int
}

func (s *server) view() pageView {
	snap := s.src.Snapshot()
	local := instanceView{Snapshot: snap, Name: s.opt.Instance, Local: true, Zones: groupByZone(snap.Records)}
	p := pageView{Local: local, Instances: []instanceView{local}, Multi: s.opt.Remotes != nil}
	for _, r := range s.remotes() {
		p.Instances = append(p.Instances, instanceView{
			Snapshot: r.Status, Name: r.Instance, Stale: r.Stale, LastReport: r.Received,
			Zones: groupByZone(r.Status.Records),
		})
	}
	zones := map[string]bool{}
	p.Healthy = true
	for _, in := range p.Instances {
		p.OK += in.OK
		p.Errors += in.Errors
		p.Pending += in.Pending
		if in.Stale {
			p.Stale++
		}
		p.Healthy = p.Healthy && in.Healthy && !in.Stale
		for _, z := range in.Zones {
			zones[z.Zone] = true
		}
	}
	p.Zones = len(zones)
	return p
}

// groupByZone sorts the records into one group per zone, in zone order.
// Records keep their configured order inside a zone.
func groupByZone(records []agent.RecordStatus) []zoneView {
	idx := map[string]int{}
	var zones []zoneView
	for _, r := range records {
		i, ok := idx[r.Zone]
		if !ok {
			i = len(zones)
			idx[r.Zone] = i
			zones = append(zones, zoneView{Zone: r.Zone})
		}
		z := &zones[i]
		host := "@"
		switch {
		case r.Zone == "":
			host = r.FQDN
		case r.FQDN != r.Zone:
			host = strings.TrimSuffix(r.FQDN, "."+r.Zone)
		}
		z.Records = append(z.Records, recordView{RecordStatus: r, Host: host})
		switch r.State {
		case agent.StateOK:
			z.OK++
		case agent.StateError:
			z.Errors++
		default:
			z.Pending++
		}
	}
	sort.SliceStable(zones, func(i, j int) bool { return zones[i].Zone < zones[j].Zone })
	return zones
}

func (s *server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.page.Execute(w, s.view()); err != nil {
		s.opt.Logger.Error("rendering status page", "error", err.Error())
	}
}

func (s *server) formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

func (s *server) ago(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := s.opt.Now().Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var v string
	switch {
	case d < time.Minute:
		v = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		v = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		v = fmt.Sprintf("%dh", int(d.Hours()))
	default:
		v = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if future {
		return "in " + v
	}
	return v + " ago"
}
