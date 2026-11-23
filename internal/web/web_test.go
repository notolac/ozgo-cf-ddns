package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/agent"
)

type staticSource agent.Snapshot

func (s staticSource) Snapshot() agent.Snapshot { return agent.Snapshot(s) }

var now = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func snapshot(healthy bool) staticSource {
	st := agent.StateOK
	errs, ok := 0, 1
	if !healthy {
		st, errs, ok = agent.StateError, 1, 0
	}
	p := true
	return staticSource{
		Version: "test", Schedule: "*/5 * * * *", Started: now.Add(-time.Hour),
		RoundStart: now.Add(-time.Minute), RoundEnd: now.Add(-50 * time.Second), NextRound: now.Add(4 * time.Minute),
		Healthy: healthy, OK: ok, Errors: errs,
		Records: []agent.RecordStatus{{
			Name: "www", FQDN: "www.example.com", Type: "A", Proxied: true, Source: "public", State: st,
			DesiredIP: "198.51.100.1", CloudflareIP: "198.51.100.1", CloudflareProxied: &p,
			LastCheck: now.Add(-50 * time.Second), LastError: "<script>alert(1)</script>",
		}},
	}
}

func get(t *testing.T, h http.Handler, path string, auth ...string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if len(auth) == 2 {
		req.SetBasicAuth(auth[0], auth[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIndexRendersAndEscapes(t *testing.T) {
	h := Handler(snapshot(false), Options{Now: func() time.Time { return now }})
	r := get(t, h, "/")
	b := body(t, r)
	if r.StatusCode != 200 || !strings.Contains(b, "www.example.com") || !strings.Contains(b, "50s ago") {
		t.Fatalf("status %d body:\n%s", r.StatusCode, b)
	}
	if strings.Contains(b, "<script>") {
		t.Fatal("error text not escaped")
	}
	if !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("missing CSP")
	}
}

func TestAPIStatus(t *testing.T) {
	h := Handler(snapshot(true), Options{})
	r := get(t, h, "/api/status")
	var snap agent.Snapshot
	if err := json.Unmarshal([]byte(body(t, r)), &snap); err != nil {
		t.Fatal(err)
	}
	if !snap.Healthy || len(snap.Records) != 1 || snap.Records[0].FQDN != "www.example.com" {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestHealthz(t *testing.T) {
	if r := get(t, Handler(snapshot(true), Options{}), "/healthz"); r.StatusCode != 200 {
		t.Fatalf("healthy: %d", r.StatusCode)
	}
	r := get(t, Handler(snapshot(false), Options{}), "/healthz")
	b := body(t, r)
	if r.StatusCode != 503 || strings.Contains(b, "example.com") {
		t.Fatalf("unhealthy: %d %q", r.StatusCode, b)
	}
	if r := get(t, Handler(staticSource{}, Options{}), "/healthz"); r.StatusCode != 503 {
		t.Fatalf("starting: %d", r.StatusCode)
	}
}

func TestBasicAuth(t *testing.T) {
	h := Handler(snapshot(true), Options{User: "admin", Password: "pw"})
	for _, p := range []string{"/", "/api/status"} {
		if r := get(t, h, p); r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s without auth: %d", p, r.StatusCode)
		}
		if r := get(t, h, p, "admin", "wrong"); r.StatusCode != 401 {
			t.Errorf("%s with wrong password: %d", p, r.StatusCode)
		}
		if r := get(t, h, p, "admin", "pw"); r.StatusCode != 200 {
			t.Errorf("%s with auth: %d", p, r.StatusCode)
		}
	}
	if r := get(t, h, "/healthz"); r.StatusCode != 200 {
		t.Errorf("healthz must stay open: %d", r.StatusCode)
	}
}

func TestUnknownPathAndMethod(t *testing.T) {
	h := Handler(snapshot(true), Options{})
	if r := get(t, h, "/nope"); r.StatusCode != 404 {
		t.Errorf("unknown path: %d", r.StatusCode)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}
