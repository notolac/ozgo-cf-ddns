// Package cloudflare is a minimal client for the Cloudflare v4 DNS API.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the Cloudflare v4 API endpoint.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// Auth holds API credentials. With Email empty, Token is an API token sent as
// a bearer token; otherwise it is the legacy global API key.
type Auth struct {
	Token string
	Email string
}

// Client talks to the Cloudflare API. The zero value uses DefaultBaseURL and
// a client with a 30 s timeout.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

// DNSRecord is the subset of a Cloudflare DNS record the agent uses.
type DNSRecord struct {
	ID         string    `json:"id,omitempty"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Content    string    `json:"content"`
	Proxied    bool      `json:"proxied"`
	TTL        int       `json:"ttl,omitempty"`
	ModifiedOn time.Time `json:"modified_on,omitzero"`
}

// APIError is a failed API call.
type APIError struct {
	Status   int
	Messages []string
}

func (e *APIError) Error() string {
	if len(e.Messages) == 0 {
		return fmt.Sprintf("cloudflare API: HTTP %d", e.Status)
	}
	return fmt.Sprintf("cloudflare API: HTTP %d: %s", e.Status, strings.Join(e.Messages, "; "))
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(ctx context.Context, auth Auth, method, path string, query url.Values, body, out any) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u := strings.TrimSuffix(base, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if auth.Email != "" {
		req.Header.Set("X-Auth-Email", auth.Email)
		req.Header.Set("X-Auth-Key", auth.Token)
	} else {
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// Strip the URL query from transport errors; it never holds secrets,
		// but keeps logs short.
		return fmt.Errorf("%s %s: %w", method, path, unwrapURLError(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%s %s: reading response: %w", method, path, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return &APIError{Status: resp.StatusCode, Messages: []string{"response is not JSON"}}
	}
	if resp.StatusCode >= 300 || !env.Success {
		e := &APIError{Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Messages = append(e.Messages, fmt.Sprintf("%d %s", m.Code, m.Message))
		}
		return e
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("%s %s: decoding result: %w", method, path, err)
		}
	}
	return nil
}

func unwrapURLError(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}

// ZoneID returns the ID of the zone with the given name.
func (c *Client) ZoneID(ctx context.Context, auth Auth, name string) (string, error) {
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	q := url.Values{"name": {name}}
	if err := c.do(ctx, auth, http.MethodGet, "/zones", q, nil, &zones); err != nil {
		return "", err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("zone %s not found or not visible to these credentials", name)
}

// ListRecords returns the records of the given type and exact name.
func (c *Client) ListRecords(ctx context.Context, auth Auth, zoneID, typ, name string) ([]DNSRecord, error) {
	var recs []DNSRecord
	q := url.Values{"type": {typ}, "name": {name}, "per_page": {"100"}}
	if err := c.do(ctx, auth, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", q, nil, &recs); err != nil {
		return nil, err
	}
	out := recs[:0]
	for _, r := range recs {
		if r.Type == typ && strings.EqualFold(r.Name, name) {
			out = append(out, r)
		}
	}
	return out, nil
}

// CreateRecord creates a record with automatic TTL.
func (c *Client) CreateRecord(ctx context.Context, auth Auth, zoneID string, rec DNSRecord) (DNSRecord, error) {
	if rec.TTL == 0 {
		rec.TTL = 1
	}
	var out DNSRecord
	err := c.do(ctx, auth, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, rec, &out)
	return out, err
}

// UpdateRecord changes the content and proxy flag of a record and keeps its
// other settings (TTL, comment, tags).
func (c *Client) UpdateRecord(ctx context.Context, auth Auth, zoneID, recordID, content string, proxied bool) (DNSRecord, error) {
	body := map[string]any{"content": content, "proxied": proxied}
	var out DNSRecord
	err := c.do(ctx, auth, http.MethodPatch, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, body, &out)
	return out, err
}

// DeleteRecord removes a record.
func (c *Client) DeleteRecord(ctx context.Context, auth Auth, zoneID, recordID string) error {
	return c.do(ctx, auth, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil, nil)
}
