package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/cloudflare"
	"github.com/notolac/ozgo-cf-ddns/internal/config"
)

// fakeCF is an in-memory Cloudflare API covering the endpoints the agent uses.
type fakeCF struct {
	mu      sync.Mutex
	zones   map[string]string // name -> id
	tokens  map[string]string // token -> zone name it may access ("*" = all)
	records map[string]*cloudflare.DNSRecord
	down    bool // simulate no connectivity (HTTP 503 from every call)
	nextID  int
	calls   map[string]int
	zoneIDs map[string]string // overrides returned zone IDs (to simulate stale IDs)
}

func newFakeCF() *fakeCF {
	return &fakeCF{
		zones:   map[string]string{"example.com": "zone-com", "example.org": "zone-org"},
		tokens:  map[string]string{"good": "*"},
		records: map[string]*cloudflare.DNSRecord{},
		calls:   map[string]int{},
		zoneIDs: map[string]string{},
	}
}

func (f *fakeCF) add(zoneID, typ, name, content string, proxied bool) string {
	f.nextID++
	id := fmt.Sprintf("rec-%d", f.nextID)
	f.records[id] = &cloudflare.DNSRecord{ID: id, Type: typ, Name: name, Content: content, Proxied: proxied,
		ModifiedOn: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	_ = zoneID
	return id
}

func (f *fakeCF) get(name string) *cloudflare.DNSRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		if r.Name == name {
			c := *r
			return &c
		}
	}
	return nil
}

func reply(w http.ResponseWriter, status int, result any, errs ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	type msg struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	var em []msg
	for _, e := range errs {
		em = append(em, msg{1000, e})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": status < 300, "errors": em, "result": result})
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.Method]++
	if f.down {
		reply(w, http.StatusServiceUnavailable, nil, "unavailable")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	scope, ok := f.tokens[token]
	if !ok {
		reply(w, http.StatusForbidden, nil, "invalid token")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "zones":
		name := r.URL.Query().Get("name")
		var out []map[string]string
		if id, ok := f.zones[name]; ok && (scope == "*" || scope == name) {
			if o, ok := f.zoneIDs[name]; ok {
				id = o
			}
			out = append(out, map[string]string{"id": id, "name": name})
		}
		reply(w, 200, out)
	case len(parts) >= 3 && parts[0] == "zones" && parts[2] == "dns_records":
		known := false
		for name, id := range f.zones {
			if id == parts[1] && (scope == "*" || scope == name) {
				known = true
			}
		}
		if !known {
			reply(w, http.StatusNotFound, nil, "zone not found")
			return
		}
		f.records2(w, r, parts)
	default:
		reply(w, http.StatusNotFound, nil, "no route")
	}
}

func (f *fakeCF) records2(w http.ResponseWriter, r *http.Request, parts []string) {
	switch {
	case r.Method == http.MethodGet && len(parts) == 3:
		q := r.URL.Query()
		out := []cloudflare.DNSRecord{}
		for _, rec := range f.records {
			if rec.Type == q.Get("type") && rec.Name == q.Get("name") {
				out = append(out, *rec)
			}
		}
		reply(w, 200, out)
	case r.Method == http.MethodPost && len(parts) == 3:
		var rec cloudflare.DNSRecord
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &rec)
		f.nextID++
		rec.ID = fmt.Sprintf("rec-%d", f.nextID)
		rec.ModifiedOn = time.Now().UTC()
		f.records[rec.ID] = &rec
		reply(w, 200, rec)
	case r.Method == http.MethodPatch && len(parts) == 4:
		rec, ok := f.records[parts[3]]
		if !ok {
			reply(w, 404, nil, "record not found")
			return
		}
		var body struct {
			Content string `json:"content"`
			Proxied bool   `json:"proxied"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		rec.Content, rec.Proxied, rec.ModifiedOn = body.Content, body.Proxied, time.Now().UTC()
		reply(w, 200, *rec)
	case r.Method == http.MethodDelete && len(parts) == 4:
		delete(f.records, parts[3])
		reply(w, 200, map[string]string{"id": parts[3]})
	default:
		reply(w, 405, nil, "method")
	}
}

// fakePublic returns a configurable public IP.
type fakePublic struct {
	mu    sync.Mutex
	addr  netip.Addr
	err   error
	calls int
}

func (p *fakePublic) set(addr string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addr, p.err = netip.MustParseAddr(addr), err
}

func (p *fakePublic) Detect(context.Context, bool, string) (netip.Addr, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.addr, "fake", p.err
}

type harness struct {
	cf     *fakeCF
	pub    *fakePublic
	agent  *Agent
	logs   *strings.Builder
	server *httptest.Server
}

func newHarness(t *testing.T, env ...string) *harness {
	t.Helper()
	cfg, err := config.Load(env)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cf := newFakeCF()
	srv := httptest.NewServer(cf)
	t.Cleanup(srv.Close)
	pub := &fakePublic{}
	pub.set("198.51.100.1", nil)
	logs := &strings.Builder{}
	h := &harness{cf: cf, pub: pub, logs: logs, server: srv}
	h.agent = New(cfg, Options{
		Version:    "test",
		Logger:     slog.New(slog.NewTextHandler(&lockedWriter{w: logs}, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Cloudflare: &cloudflare.Client{BaseURL: srv.URL},
		Public:     pub,
	})
	return h
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

var twoRecords = []string{
	"API_KEY=good", "ZONE=example.com",
	"SUBDOMAIN_WWW=www", "PROXIED_WWW=true",
	"ZONE_LAN=example.org", "SUBDOMAIN_LAN=lan", "STATIC_IP_LAN=192.0.2.20",
}

func (h *harness) state(t *testing.T, fqdn string) RecordStatus {
	t.Helper()
	for _, r := range h.agent.Status().Snapshot().Records {
		if r.FQDN == fqdn {
			return r
		}
	}
	t.Fatalf("no status for %s", fqdn)
	return RecordStatus{}
}

func TestCreatesMissingRecords(t *testing.T) {
	h := newHarness(t, twoRecords...)
	if failed := h.agent.Round(context.Background()); failed != 0 {
		t.Fatalf("failed = %d\n%s", failed, h.logs)
	}
	www := h.cf.get("www.example.com")
	if www == nil || www.Content != "198.51.100.1" || !www.Proxied {
		t.Fatalf("www = %+v", www)
	}
	lan := h.cf.get("lan.example.org")
	if lan == nil || lan.Content != "192.0.2.20" || lan.Proxied {
		t.Fatalf("lan = %+v", lan)
	}
	snap := h.agent.Status().Snapshot()
	if !snap.Healthy || snap.OK != 2 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestUpdatesChangedIPAndKeepsInSyncRecords(t *testing.T) {
	h := newHarness(t, twoRecords...)
	h.agent.Round(context.Background())
	patches := h.cf.calls[http.MethodPatch]

	h.agent.Round(context.Background())
	if h.cf.calls[http.MethodPatch] != patches {
		t.Fatal("in-sync records were rewritten")
	}

	h.pub.set("198.51.100.2", nil)
	h.agent.Round(context.Background())
	if got := h.cf.get("www.example.com").Content; got != "198.51.100.2" {
		t.Fatalf("www content = %s", got)
	}
	if got := h.cf.get("lan.example.org").Content; got != "192.0.2.20" {
		t.Fatalf("static record changed: %s", got)
	}
	if st := h.state(t, "www.example.com"); st.LastChange.IsZero() || st.CloudflareIP != "198.51.100.2" {
		t.Fatalf("status = %+v", st)
	}
}

func TestPublicIPDetectedOncePerRound(t *testing.T) {
	h := newHarness(t, "API_KEY=good", "ZONE=example.com", "SUBDOMAIN_A=a", "SUBDOMAIN_B=b", "SUBDOMAIN_C=c")
	h.agent.Round(context.Background())
	if h.pub.calls != 1 {
		t.Fatalf("public IP detected %d times in one round", h.pub.calls)
	}
}

func TestCorrectsProxyDrift(t *testing.T) {
	h := newHarness(t, twoRecords...)
	h.cf.add("zone-com", "A", "www.example.com", "198.51.100.1", false)
	h.agent.Round(context.Background())
	if !h.cf.get("www.example.com").Proxied {
		t.Fatal("proxy flag not corrected while the IP was unchanged")
	}
}

// Regression for the oznu bug: a container started without WAN cached an
// empty record ID and never recovered. Here the first rounds fail and a later
// round must succeed in the same process.
func TestRecoversAfterStartingWithoutConnectivity(t *testing.T) {
	h := newHarness(t, twoRecords...)
	h.cf.add("zone-com", "A", "www.example.com", "203.0.113.50", true)
	h.cf.down = true
	h.pub.set("198.51.100.1", errors.New("network is unreachable"))

	for range 3 {
		if failed := h.agent.Round(context.Background()); failed != 2 {
			t.Fatalf("failed = %d, want 2", failed)
		}
	}
	st := h.state(t, "www.example.com")
	if st.State != StateError || st.Failures != 3 || st.LastError == "" {
		t.Fatalf("status while offline = %+v", st)
	}
	if h.agent.Status().Snapshot().Healthy {
		t.Fatal("healthy while failing")
	}

	h.cf.mu.Lock()
	h.cf.down = false
	h.cf.mu.Unlock()
	h.pub.set("198.51.100.1", nil)
	if failed := h.agent.Round(context.Background()); failed != 0 {
		t.Fatalf("failed after recovery = %d\n%s", failed, h.logs)
	}
	if got := h.cf.get("www.example.com").Content; got != "198.51.100.1" {
		t.Fatalf("record not updated after recovery: %s", got)
	}
	if st := h.state(t, "www.example.com"); st.State != StateOK || st.Failures != 0 {
		t.Fatalf("status after recovery = %+v", st)
	}
	if !strings.Contains(h.logs.String(), "record recovered") {
		t.Fatal("recovery not logged")
	}
}

func TestZoneFailureDoesNotBlockOthers(t *testing.T) {
	h := newHarness(t,
		"API_KEY=good", "ZONE=example.com", "SUBDOMAIN_OK=ok",
		"ZONE_BAD=example.org", "SUBDOMAIN_BAD=bad", "API_KEY_BAD=revoked",
	)
	if failed := h.agent.Round(context.Background()); failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
	if h.cf.get("ok.example.com") == nil {
		t.Fatal("healthy zone not updated")
	}
	if st := h.state(t, "bad.example.org"); st.State != StateError {
		t.Fatalf("bad = %+v", st)
	}
}

func TestStaleZoneIDIsRefreshed(t *testing.T) {
	h := newHarness(t, twoRecords...)
	h.cf.zoneIDs["example.com"] = "zone-stale"
	if failed := h.agent.Round(context.Background()); failed != 1 {
		t.Fatalf("failed = %d, want 1 (stale zone)", failed)
	}
	delete(h.cf.zoneIDs, "example.com")
	if failed := h.agent.Round(context.Background()); failed != 0 {
		t.Fatalf("stale zone ID was kept: failed = %d\n%s", failed, h.logs)
	}
}

func TestDeleteOnStop(t *testing.T) {
	h := newHarness(t, "API_KEY=good", "ZONE=example.com", "SUBDOMAIN_TMP=tmp", "DELETE_ON_STOP_TMP=true", "SUBDOMAIN_KEEP=keep")
	h.agent.opt.BaseBackoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.agent.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for h.cf.get("tmp.example.com") == nil || h.cf.get("keep.example.com") == nil {
		if time.Now().After(deadline) {
			t.Fatal("records not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if h.cf.get("tmp.example.com") != nil {
		t.Fatal("DELETE_ON_STOP record still present")
	}
	if h.cf.get("keep.example.com") == nil {
		t.Fatal("record without DELETE_ON_STOP was deleted")
	}
}

func TestLogsNeverContainToken(t *testing.T) {
	h := newHarness(t, "API_KEY=good", "ZONE=example.com", "SUBDOMAIN_A=a",
		"ZONE_B=example.org", "SUBDOMAIN_B=b", "API_KEY_B=s3cr3t-token-value")
	h.agent.Round(context.Background())
	snap, _ := json.Marshal(h.agent.Status().Snapshot())
	for _, out := range []string{h.logs.String(), string(snap)} {
		if strings.Contains(out, "s3cr3t-token-value") {
			t.Fatal("token leaked into logs or status")
		}
	}
}

func TestBackoff(t *testing.T) {
	a := &Agent{opt: Options{BaseBackoff: 30 * time.Second, MaxBackoff: 5 * time.Minute}}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := a.backoff(i + 1); got != w {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w)
		}
	}
}

func TestChangesSignalsAfterEveryRoundWithoutBlocking(t *testing.T) {
	h := newHarness(t, "API_KEY=good", "ZONE=example.com", "SUBDOMAIN=www")
	ch := h.agent.Status().Changes()
	for range 3 { // nobody reads: the agent must not block
		h.agent.Round(context.Background())
	}
	select {
	case <-ch:
	default:
		t.Fatal("no change signalled")
	}
	select {
	case <-ch:
		t.Fatal("notifications should be coalesced")
	default:
	}
}
