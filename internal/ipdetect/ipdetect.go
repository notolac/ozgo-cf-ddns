// Package ipdetect finds the IP address a record should point to.
package ipdetect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// Default resolvers for public IP detection (Cloudflare answers whoami.cloudflare).
const (
	DefaultDNSServer4 = "1.1.1.1"
	DefaultDNSServer6 = "2606:4700:4700::1111"
)

// Default HTTPS fallback endpoints. They return "ip=<address>" in plain text.
const (
	DefaultTraceURL4 = "https://1.1.1.1/cdn-cgi/trace"
	DefaultTraceURL6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
)

// Public detects the public IP address of this host. The zero value is ready
// to use.
type Public struct {
	HTTP      *http.Client // defaults to a client with a 10 s timeout
	TraceURL4 string
	TraceURL6 string
	Timeout   time.Duration // per method; default 5 s
}

func (p *Public) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 5 * time.Second
}

// Detect returns the public address of the requested family and the method
// that found it ("dns" or "https"). dnsServer may be empty.
func (p *Public) Detect(ctx context.Context, v6 bool, dnsServer string) (netip.Addr, string, error) {
	if dnsServer == "" {
		dnsServer = DefaultDNSServer4
		if v6 {
			dnsServer = DefaultDNSServer6
		}
	}
	dctx, cancel := context.WithTimeout(ctx, p.timeout())
	addr, dnsErr := whoami(dctx, v6, dnsServer)
	cancel()
	if dnsErr == nil {
		return addr, "dns", nil
	}

	hctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	addr, httpErr := p.trace(hctx, v6)
	if httpErr == nil {
		return addr, "https", nil
	}
	return netip.Addr{}, "", fmt.Errorf("dns via %s: %v; https: %v", dnsServer, dnsErr, httpErr)
}

func (p *Public) trace(ctx context.Context, v6 bool) (netip.Addr, error) {
	u := p.TraceURL4
	if u == "" {
		u = DefaultTraceURL4
	}
	if v6 {
		u = p.TraceURL6
		if u == "" {
			u = DefaultTraceURL6
		}
	}
	client := p.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	addr, err := parseTrace(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return netip.Addr{}, err
	}
	return checkFamily(addr, v6)
}

func parseTrace(r io.Reader) (netip.Addr, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "ip="); ok {
			return netip.ParseAddr(strings.TrimSpace(v))
		}
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, err
	}
	return netip.Addr{}, errors.New("no ip= line in trace response")
}

func checkFamily(addr netip.Addr, v6 bool) (netip.Addr, error) {
	addr = addr.Unmap()
	if addr.Is6() != v6 {
		want := "IPv4"
		if v6 {
			want = "IPv6"
		}
		return netip.Addr{}, fmt.Errorf("got %s, want an %s address", addr, want)
	}
	return addr, nil
}

// Parse validates an address returned by a lookup and checks its family.
func Parse(s string, v6 bool) (netip.Addr, error) {
	s = strings.Trim(strings.TrimSpace(s), `"'`)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	return checkFamily(addr, v6)
}

// Command runs a CUSTOM_LOOKUP_CMD with /bin/sh and parses the first non-empty
// output line.
func Command(ctx context.Context, cmd string, v6 bool) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Running an operator-supplied command is the purpose of CUSTOM_LOOKUP_CMD
	// (oznu compatibility); it comes from the container configuration only.
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", cmd).Output() // #nosec G204 -- see above
	if err != nil {
		return netip.Addr{}, fmt.Errorf("CUSTOM_LOOKUP_CMD: %w", err)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			return Parse(line, v6)
		}
	}
	return netip.Addr{}, errors.New("CUSTOM_LOOKUP_CMD printed nothing")
}

// Interface returns the first address of the given family on a network
// interface. IPv6 link-local addresses are skipped.
func Interface(name string, v6 bool) (netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is6() == v6 && addr.IsGlobalUnicast() {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s has no usable address of this family", name)
}
