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

func (s *server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.page.Execute(w, s.src.Snapshot()); err != nil {
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
