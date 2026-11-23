package ipdetect

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// response builds a DNS answer to buildQuery(id) with the given TXT strings.
func response(id uint16, flags uint16, txt ...string) []byte {
	q := buildQuery(id)
	msg := append([]byte{}, q...)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(txt)))
	for _, s := range txt {
		msg = append(msg, 0xc0, 12)                 // pointer to the question name
		msg = append(msg, 0, typeTXT, 0, classCHAO) // type, class
		msg = append(msg, 0, 0, 0, 0)               // TTL
		msg = append(msg, 0, byte(len(s)+1), byte(len(s)))
		msg = append(msg, s...)
	}
	return msg
}

func TestParseTXT(t *testing.T) {
	got, err := parseTXT(response(42, 0x8180, "198.51.100.7"), 42)
	if err != nil || len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("parseTXT = %v, %v", got, err)
	}
	if _, err := parseTXT(response(42, 0x8180, "x"), 43); err == nil {
		t.Error("ID mismatch accepted")
	}
	if _, err := parseTXT(response(42, 0x8183), 42); err == nil {
		t.Error("NXDOMAIN accepted")
	}
	if _, err := parseTXT(response(42, 0x8380, "x"), 42); err == nil {
		t.Error("truncated response accepted")
	}
	bad := response(42, 0x8180, "198.51.100.7")
	if _, err := parseTXT(bad[:len(bad)-3], 42); err == nil {
		t.Error("short rdata accepted")
	}
}

func FuzzParseTXT(f *testing.F) {
	f.Add(response(1, 0x8180, "198.51.100.7"))
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, msg []byte) {
		_, _ = parseTXT(msg, 1) // must never panic
	})
}

func TestParse(t *testing.T) {
	if a, err := Parse(` "198.51.100.7" `, false); err != nil || a.String() != "198.51.100.7" {
		t.Fatalf("Parse = %v, %v", a, err)
	}
	if _, err := Parse("198.51.100.7", true); err == nil {
		t.Error("IPv4 accepted for AAAA")
	}
	if _, err := Parse("not-an-ip", false); err == nil {
		t.Error("garbage accepted")
	}
}

func TestPublicFallsBackToHTTPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("fl=1\nh=example\nip=203.0.113.9\nts=1\n"))
	}))
	defer srv.Close()
	p := &Public{TraceURL4: srv.URL, Timeout: 500 * time.Millisecond}
	// Nothing answers DNS on this port, so detection must use HTTPS.
	addr, method, err := p.Detect(context.Background(), false, "127.0.0.1:9")
	if err != nil || method != "https" || addr.String() != "203.0.113.9" {
		t.Fatalf("Detect = %v, %s, %v", addr, method, err)
	}
}

func TestPublicReportsBothFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	p := &Public{TraceURL4: srv.URL, Timeout: 500 * time.Millisecond}
	_, _, err := p.Detect(context.Background(), false, "127.0.0.1:9")
	if err == nil || !strings.Contains(err.Error(), "dns via") || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v", err)
	}
}

func TestCommand(t *testing.T) {
	a, err := Command(context.Background(), "printf '\\n192.0.2.44\\n'", false)
	if err != nil || a.String() != "192.0.2.44" {
		t.Fatalf("Command = %v, %v", a, err)
	}
	if _, err := Command(context.Background(), "exit 3", false); err == nil {
		t.Error("failing command accepted")
	}
}
