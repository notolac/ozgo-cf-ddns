package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"z1","name":"example.com"}]}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, UserAgent: "ua/1"}

	if _, err := c.ZoneID(context.Background(), Auth{Token: "tok"}, "example.com"); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer tok" || got.Get("X-Auth-Key") != "" || got.Get("User-Agent") != "ua/1" {
		t.Fatalf("token headers: %v", got)
	}

	if _, err := c.ZoneID(context.Background(), Auth{Token: "key", Email: "ops@example.com"}, "example.com"); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "" || got.Get("X-Auth-Key") != "key" || got.Get("X-Auth-Email") != "ops@example.com" {
		t.Fatalf("global key headers: %v", got)
	}
}

func TestAPIErrorsAreReportedWithoutSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"result":null}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	_, err := c.ListRecords(context.Background(), Auth{Token: "secret-value"}, "z1", "A", "www.example.com")
	if err == nil || !strings.Contains(err.Error(), "9109 Invalid access token") || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("err = %v", err)
	}
}

func TestNonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).ZoneID(context.Background(), Auth{Token: "t"}, "example.com")
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("err = %v", err)
	}
}

func TestZoneNotVisible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).ZoneID(context.Background(), Auth{Token: "t"}, "example.com")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestListRecordsFiltersExactName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "A" || r.URL.Query().Get("name") != "www.example.com" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":[
			{"id":"1","type":"A","name":"www.example.com","content":"192.0.2.1","proxied":true},
			{"id":"2","type":"A","name":"other.example.com","content":"192.0.2.2"}]}`))
	}))
	defer srv.Close()
	recs, err := (&Client{BaseURL: srv.URL}).ListRecords(context.Background(), Auth{Token: "t"}, "z1", "A", "www.example.com")
	if err != nil || len(recs) != 1 || recs[0].ID != "1" || !recs[0].Proxied {
		t.Fatalf("recs = %+v, err = %v", recs, err)
	}
}
