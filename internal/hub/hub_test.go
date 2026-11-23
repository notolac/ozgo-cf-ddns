package hub

import (
	"bytes"
	"context"
	"encoding/json"

	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/notolac/ozgo-cf-ddns/internal/agent"
)

var (
	key = []byte("0123456789abcdef0123456789abcdef-test")
	t0  = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func snap(states ...agent.State) agent.Snapshot {
	s := agent.Snapshot{Version: "test", RoundEnd: t0, Healthy: false, OK: 99}
	for i, st := range states {
		s.Records = append(s.Records, agent.RecordStatus{
			Name: fmt.Sprint("r", i), FQDN: fmt.Sprintf("r%d.example.org", i), Zone: "example.org", State: st,
		})
	}
	return s
}

func post(t *testing.T, h http.Handler, ts int64, body []byte, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(body))
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func signed(t *testing.T, h http.Handler, ts int64, r Report) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return post(t, h, ts, body, Sign(key, ts, body))
}

func setup() (*Store, http.Handler, *clock) {
	c := &clock{t: t0}
	st := NewStore("main", c.now)
	return st, Handler(st, key, slog.New(slog.DiscardHandler)), c
}

func TestSignVerify(t *testing.T) {
	body := []byte(`{"a":1}`)
	sig := Sign(key, 42, body)
	if !strings.HasPrefix(sig, "v1=") || !Verify(key, 42, body, sig) {
		t.Fatal("valid signature rejected")
	}
	for name, ok := range map[string]bool{
		"other ts":   Verify(key, 43, body, sig),
		"other body": Verify(key, 42, []byte(`{"a":2}`), sig),
		"other key":  Verify([]byte("another-key-another-key-another-key"), 42, body, sig),
		"empty":      Verify(key, 42, body, ""),
	} {
		if ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestHandlerAcceptsAndRecounts(t *testing.T) {
	st, h, _ := setup()
	if rec := signed(t, h, t0.UnixMilli(), Report{Instance: "org", Status: snap(agent.StateOK, agent.StateError)}); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	r := st.Remotes()
	if len(r) != 1 || r[0].Instance != "org" || r[0].Stale {
		t.Fatalf("remotes = %+v", r)
	}
	if s := r[0].Status; s.OK != 1 || s.Errors != 1 || s.Healthy {
		t.Fatalf("counts not recomputed: ok=%d errors=%d healthy=%v", s.OK, s.Errors, s.Healthy)
	}
}

func TestHandlerRejects(t *testing.T) {
	ts := t0.UnixMilli()
	good, _ := json.Marshal(Report{Instance: "org", Status: snap(agent.StateOK)})
	cases := []struct {
		name string
		do   func(h http.Handler) *httptest.ResponseRecorder
		want int
	}{
		{"no signature", func(h http.Handler) *httptest.ResponseRecorder { return post(t, h, ts, good, "") }, 401},
		{"wrong key", func(h http.Handler) *httptest.ResponseRecorder {
			return post(t, h, ts, good, Sign([]byte("wrong-key-wrong-key-wrong-key-wrong"), ts, good))
		}, 401},
		{"tampered body", func(h http.Handler) *httptest.ResponseRecorder {
			return post(t, h, ts, bytes.Replace(good, []byte("org"), []byte("evil"), 1), Sign(key, ts, good))
		}, 401},
		{"old timestamp", func(h http.Handler) *httptest.ResponseRecorder {
			old := t0.Add(-MaxSkew - time.Second).UnixMilli()
			return post(t, h, old, good, Sign(key, old, good))
		}, 401},
		{"future timestamp", func(h http.Handler) *httptest.ResponseRecorder {
			f := t0.Add(MaxSkew + time.Second).UnixMilli()
			return post(t, h, f, good, Sign(key, f, good))
		}, 401},
		{"bad JSON", func(h http.Handler) *httptest.ResponseRecorder {
			b := []byte("{")
			return post(t, h, ts, b, Sign(key, ts, b))
		}, 400},
		{"bad instance", func(h http.Handler) *httptest.ResponseRecorder {
			return signed(t, h, ts, Report{Instance: "<b>x</b>", Status: snap()})
		}, 400},
		{"main's name", func(h http.Handler) *httptest.ResponseRecorder {
			return signed(t, h, ts, Report{Instance: "main", Status: snap()})
		}, 409},
		{"unknown state", func(h http.Handler) *httptest.ResponseRecorder {
			return signed(t, h, ts, Report{Instance: "org", Status: snap("evil")})
		}, 400},
		{"too large", func(h http.Handler) *httptest.ResponseRecorder {
			b := bytes.Repeat([]byte(" "), MaxBody+1)
			return post(t, h, ts, b, Sign(key, ts, b))
		}, 413},
		{"GET", func(h http.Handler) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, nil))
			return rec
		}, 405},
	}
	for _, c := range cases {
		st, h, _ := setup()
		if rec := c.do(h); rec.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body)
		}
		if len(st.Remotes()) != 0 {
			t.Errorf("%s: report stored", c.name)
		}
	}
}

func TestHandlerRejectsReplay(t *testing.T) {
	st, h, _ := setup()
	ts := t0.UnixMilli()
	body, _ := json.Marshal(Report{Instance: "org", Status: snap(agent.StateOK)})
	if rec := post(t, h, ts, body, Sign(key, ts, body)); rec.Code != 204 {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := post(t, h, ts, body, Sign(key, ts, body)); rec.Code != 409 {
		t.Fatalf("replay: %d", rec.Code)
	}
	if rec := signed(t, h, ts-1, Report{Instance: "org", Status: snap(agent.StateError)}); rec.Code != 409 {
		t.Fatalf("older: %d", rec.Code)
	}
	if st.Remotes()[0].Status.OK != 1 {
		t.Fatal("older report overwrote the newer one")
	}
}

func TestStoreLimitsStaleAndForget(t *testing.T) {
	st, h, c := setup()
	ts := t0.UnixMilli()
	for i := range MaxInstances {
		if rec := signed(t, h, ts, Report{Instance: fmt.Sprint("s", i), Status: snap()}); rec.Code != 204 {
			t.Fatalf("sidecar %d: %d", i, rec.Code)
		}
	}
	if rec := signed(t, h, ts, Report{Instance: "one-too-many", Status: snap()}); rec.Code != 429 {
		t.Fatalf("over the limit: %d", rec.Code)
	}
	c.add(StaleAfter + time.Second)
	if r := st.Remotes(); !r[0].Stale {
		t.Fatal("not marked stale")
	}
	c.add(ForgetAfter)
	if r := st.Remotes(); len(r) != 0 {
		t.Fatalf("not forgotten: %d", len(r))
	}
}

func TestStoreReturnsCopies(t *testing.T) {
	st, h, _ := setup()
	signed(t, h, t0.UnixMilli(), Report{Instance: "org", Status: snap(agent.StateOK)})
	st.Remotes()[0].Status.Records[0].FQDN = "changed"
	if st.Remotes()[0].Status.Records[0].FQDN == "changed" {
		t.Fatal("Remotes shares memory with the store")
	}
}

type fixedSource agent.Snapshot

func (f fixedSource) Snapshot() agent.Snapshot { return agent.Snapshot(f) }

// TestReporterEndToEnd runs a reporter against a real main handler and checks
// the key never appears in the request.
func TestReporterEndToEnd(t *testing.T) {
	c := &clock{t: time.Now()}
	st := NewStore("main", c.now)
	inner := Handler(st, key, slog.New(slog.DiscardHandler))
	var leaked bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		_ = r.Header.Write(&buf)
		body, _ := json.Marshal(r.URL)
		mu.Lock()
		leaked = leaked || bytes.Contains(buf.Bytes(), key) || bytes.Contains(body, key)
		mu.Unlock()
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()

	rep := &Reporter{URL: srv.URL, Key: key, Instance: "org", Source: fixedSource(snap(agent.StateOK)), Client: srv.Client()}
	for range 3 { // same millisecond on fast machines: timestamps must still increase
		if err := rep.Send(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r := st.Remotes(); len(r) != 1 || r[0].Instance != "org" {
		t.Fatalf("remotes = %+v", r)
	}
	if leaked {
		t.Fatal("SYNC_KEY sent over the wire")
	}

	bad := &Reporter{URL: srv.URL, Key: []byte("not-the-right-key-not-the-right-key"), Instance: "x", Source: fixedSource(snap()), Client: srv.Client()}
	if err := bad.Send(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong key: %v", err)
	}
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestReporterRecovers starts with the main container down: reporting must
// resume on its own once it is back, and the log must not contain the key.
func TestReporterRecovers(t *testing.T) {
	st := NewStore("main", nil)
	inner := Handler(st, key, slog.New(slog.DiscardHandler))
	var mu sync.Mutex
	up := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := up
		mu.Unlock()
		if !ok {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()

	logs := &logBuf{}
	rep := &Reporter{URL: srv.URL, Key: key, Instance: "org", Source: fixedSource(snap(agent.StateOK)),
		Client: srv.Client(), Interval: 10 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(logs, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rep.Run(ctx, nil); close(done) }()

	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	up = true
	mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for len(st.Remotes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(st.Remotes()) != 1 {
		t.Fatal("reporter did not recover")
	}
	out := logs.String()
	if !strings.Contains(out, "cannot report to the main container") || !strings.Contains(out, "reporting to the main container restored") {
		t.Fatalf("logs:\n%s", out)
	}
	if strings.Contains(out, string(key)) {
		t.Fatal("key in logs")
	}
}
