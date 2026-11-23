// Package web serves the read-only status interface.
//
//	GET /             HTML status page (refreshes every 30 s)
//	GET /api/status   the same data as JSON
//	GET /healthz      200 when every record is in sync, 503 otherwise
//
// When a user and password are configured, / and /api/status require HTTP
// basic auth. /healthz stays open for the container health check and only
// returns counts, never record names.
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
)

//go:embed templates/index.html
var files embed.FS

// Source provides the state to display.
type Source interface {
	Snapshot() agent.Snapshot
}

// Options configure the handler.
type Options struct {
	User     string
	Password string
	Logger   *slog.Logger
	Now      func() time.Time
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

func (s *server) api(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.src.Snapshot()); err != nil {
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

type pageView struct {
	agent.Snapshot
	Zones []zoneView
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
		if r.FQDN != r.Zone {
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
	snap := s.src.Snapshot()
	if err := s.page.Execute(w, pageView{Snapshot: snap, Zones: groupByZone(snap.Records)}); err != nil {
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
