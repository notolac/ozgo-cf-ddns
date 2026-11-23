// Package config loads the agent configuration from environment variables.
//
// It keeps the variable names of oznu/cloudflare-ddns. A container with one
// record uses the plain names (ZONE, SUBDOMAIN, PROXIED, ...). A container with
// several records adds a per-record suffix (ZONE_BLOG, SUBDOMAIN_BLOG, ...).
// Unsuffixed values then act as defaults for every record, except SUBDOMAIN,
// which always belongs to a single record.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/notolac/ozgo-cf-ddns/internal/cron"
)

// DefaultSchedule matches the oznu default: every five minutes.
const DefaultSchedule = "*/5 * * * *"

// Source says where a record gets its IP address from.
type Source string

const (
	SourcePublic    Source = "public"    // detected public IP of this host
	SourceStatic    Source = "static"    // STATIC_IP, or CUSTOM_LOOKUP_CMD=echo <ip>
	SourceCommand   Source = "command"   // any other CUSTOM_LOOKUP_CMD
	SourceInterface Source = "interface" // first address of INTERFACE
)

// Credentials authenticate against the Cloudflare API. With Email empty, Token
// is an API token; with Email set, Token is the legacy global API key.
type Credentials struct {
	Token string
	Email string
}

// Kind describes the credential type without revealing it.
func (c Credentials) Kind() string {
	if c.Email != "" {
		return "global-api-key"
	}
	return "api-token"
}

// String never prints the secret.
func (c Credentials) String() string { return "[redacted " + c.Kind() + "]" }

// LogValue keeps secrets out of structured logs.
func (c Credentials) LogValue() slog.Value { return slog.StringValue(c.String()) }

// Record is one DNS record kept up to date by the agent.
type Record struct {
	Name         string // identifier: lowercased suffix, or "default"
	Zone         string
	Subdomain    string // empty for the zone apex
	Type         string // A or AAAA
	Proxied      bool
	DeleteOnStop bool
	Credentials  Credentials
	Source       Source
	StaticIP     netip.Addr // SourceStatic
	LookupCmd    string     // SourceCommand
	Interface    string     // SourceInterface
	DNSServer    string     // resolver for public IP detection; empty = default
}

// FQDN returns the fully qualified record name.
func (r Record) FQDN() string {
	if r.Subdomain == "" {
		return r.Zone
	}
	return r.Subdomain + "." + r.Zone
}

// IPv6 reports whether the record is an AAAA record.
func (r Record) IPv6() bool { return r.Type == "AAAA" }

// Secret is a string that never prints its value.
type Secret string

// String never prints the secret.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// LogValue keeps secrets out of structured logs.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// MinSyncKeyLength is the shortest accepted SYNC_KEY.
const MinSyncKeyLength = 32

// Sync links several containers to one status page. The main container sets
// only Key and accepts reports; a sidecar also sets URL and reports to it.
type Sync struct {
	Key      Secret // SYNC_KEY: shared key used to sign reports (HMAC-SHA256)
	URL      string // SYNC_URL: base URL of the main container (sidecars only)
	Instance string // INSTANCE_NAME: label of this container on the status page
}

// Sidecar reports whether this container sends its status to a main container.
func (s Sync) Sidecar() bool { return s.URL != "" }

// Main reports whether this container accepts reports from sidecars.
func (s Sync) Main() bool { return s.Key != "" && s.URL == "" }

// Web configures the status interface.
type Web struct {
	Enabled  bool
	Port     int
	User     string
	Password string
}

// Config is the complete agent configuration.
type Config struct {
	Records   []Record
	Schedule  *cron.Schedule
	Web       Web
	Sync      Sync
	LogLevel  slog.Level
	LogFormat string // text or json
	Warnings  []string
}

// Per-record keys. Each one also accepts a <KEY>_<NAME> form.
var recordKeys = []string{
	"API_KEY", "API_KEY_FILE", "EMAIL",
	"ZONE", "ZONE_FILE", "SUBDOMAIN", "SUBDOMAIN_FILE",
	"PROXIED", "RRTYPE", "DELETE_ON_STOP",
	"STATIC_IP", "CUSTOM_LOOKUP_CMD", "INTERFACE", "DNS_SERVER",
}

// Keys that can be read from a file through <KEY>_FILE.
var fileKeys = map[string]bool{"API_KEY": true, "ZONE": true, "SUBDOMAIN": true}

// Keys whose presence declares a record.
var definingKeys = []string{"ZONE", "ZONE_FILE", "SUBDOMAIN", "SUBDOMAIN_FILE"}

var sourceKeys = []string{"STATIC_IP", "CUSTOM_LOOKUP_CMD", "INTERFACE"}

var (
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9]+(_[A-Za-z0-9]+)*$`)
	instanceRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62})$`)
	echoRE     = regexp.MustCompile(`^echo\s+["']?([0-9A-Fa-f:.]+)["']?$`)
)

func init() {
	// Longest key first, so ZONE_FILE_BLOG is read as ZONE_FILE + BLOG.
	sort.SliceStable(recordKeys, func(i, j int) bool { return len(recordKeys[i]) > len(recordKeys[j]) })
}

// splitKey maps an environment variable to a record key and record name.
// ok is false for variables that are not record keys.
func splitKey(envKey string) (key, name string, ok bool) {
	for _, k := range recordKeys {
		if envKey == k {
			return k, "", true
		}
		if rest, found := strings.CutPrefix(envKey, k+"_"); found && rest != "" {
			return k, rest, true
		}
	}
	return "", "", false
}

type scope map[string]string

type envSet struct {
	vars   map[string]string
	global scope
	per    map[string]scope // record name -> keys
}

// value returns a record setting: the suffixed variable first, then (when
// fallback is true) the unsuffixed default. <KEY>_FILE variants are read from
// disk.
func (e *envSet) value(name, key string, fallback bool) (string, bool, error) {
	scopes := []scope{e.per[name]}
	if fallback && name != "" {
		scopes = append(scopes, e.global)
	}
	for _, s := range scopes {
		if v, ok := s[key]; ok {
			return strings.TrimSpace(v), true, nil
		}
		if !fileKeys[key] {
			continue
		}
		if p, ok := s[key+"_FILE"]; ok {
			b, err := os.ReadFile(strings.TrimSpace(p))
			if err != nil {
				return "", true, fmt.Errorf("%s_FILE: %w", key, err)
			}
			return strings.TrimSpace(string(b)), true, nil
		}
	}
	return "", false, nil
}

func (e *envSet) bool(name, key string, def bool) (bool, error) {
	v, ok, err := e.value(name, key, true)
	if err != nil || !ok || v == "" {
		return def, err
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s: %q is not a boolean (use true or false)", key, v)
	}
	return b, nil
}

// Load builds the configuration from environ, in os.Environ format.
func Load(environ []string) (*Config, error) {
	e := &envSet{vars: map[string]string{}, global: scope{}, per: map[string]scope{}}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			e.vars[k] = v
		}
	}

	var errs []error
	for k, v := range e.vars {
		key, name, ok := splitKey(k)
		if !ok {
			continue
		}
		if name == "" {
			e.global[key] = v
			continue
		}
		if !nameRE.MatchString(name) || strings.HasPrefix(name, "FILE") {
			errs = append(errs, fmt.Errorf("%s: invalid record name %q", k, name))
			continue
		}
		if e.per[name] == nil {
			e.per[name] = scope{}
		}
		e.per[name][key] = v
	}

	cfg := &Config{}
	names := make([]string, 0, len(e.per))
	for name, s := range e.per {
		if !slices.ContainsFunc(definingKeys, func(k string) bool { _, ok := s[k]; return ok }) {
			errs = append(errs, fmt.Errorf("record %s: variables set but neither ZONE_%s nor SUBDOMAIN_%s defines it", name, name, name))
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	switch {
	case len(e.per) == 0:
		// Single record, oznu style.
		if _, ok := e.global["ZONE"]; !ok {
			if _, ok := e.global["ZONE_FILE"]; !ok {
				errs = append(errs, errors.New("no records configured: set ZONE (one record) or ZONE_<NAME>/SUBDOMAIN_<NAME> (several records)"))
			}
		}
		if len(errs) == 0 {
			e.per[""] = e.global
			names = []string{""}
		}
	default:
		for _, k := range []string{"SUBDOMAIN", "SUBDOMAIN_FILE"} {
			if _, ok := e.global[k]; ok {
				errs = append(errs, fmt.Errorf("%s without a suffix cannot be combined with per-record variables; use SUBDOMAIN_<NAME>", k))
			}
		}
	}

	seen := map[string]string{}
	for _, name := range names {
		r, err := e.record(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("record %s: %w", displayName(name), err))
			continue
		}
		id := r.Type + " " + r.FQDN()
		if other, dup := seen[id]; dup {
			errs = append(errs, fmt.Errorf("records %s and %s both manage %s", other, r.Name, id))
			continue
		}
		seen[id] = r.Name
		cfg.Records = append(cfg.Records, r)
	}

	if err := e.globals(cfg); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

func displayName(name string) string {
	if name == "" {
		return "default"
	}
	return strings.ToLower(name)
}

func normalizeDNSName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (e *envSet) record(name string) (Record, error) {
	r := Record{Name: displayName(name), Type: "A"}
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	zone, _, err := e.value(name, "ZONE", true)
	collect(err)
	r.Zone = normalizeDNSName(zone)
	if r.Zone == "" && err == nil {
		errs = append(errs, errors.New("ZONE is empty"))
	}

	sub, _, err := e.value(name, "SUBDOMAIN", false)
	collect(err)
	r.Subdomain = normalizeDNSName(sub)
	if r.Subdomain == "@" {
		r.Subdomain = ""
	}

	if t, ok, _ := e.value(name, "RRTYPE", true); ok && t != "" {
		r.Type = strings.ToUpper(t)
	}
	if r.Type != "A" && r.Type != "AAAA" {
		errs = append(errs, fmt.Errorf("RRTYPE %q is not supported (use A or AAAA)", r.Type))
	}

	r.Proxied, err = e.bool(name, "PROXIED", false)
	collect(err)
	r.DeleteOnStop, err = e.bool(name, "DELETE_ON_STOP", false)
	collect(err)

	token, _, err := e.value(name, "API_KEY", true)
	collect(err)
	if token == "" && err == nil {
		errs = append(errs, errors.New("API_KEY is empty"))
	}
	email, _, _ := e.value(name, "EMAIL", true)
	r.Credentials = Credentials{Token: token, Email: email}

	r.DNSServer, _, _ = e.value(name, "DNS_SERVER", true)

	collect(e.source(name, &r))
	return r, errors.Join(errs...)
}

// source picks the IP source. Per-record source variables replace the
// unsuffixed defaults as a whole.
func (e *envSet) source(name string, r *Record) error {
	pick := func(s scope) (string, string, error) {
		var found []string
		for _, k := range sourceKeys {
			if v, ok := s[k]; ok && strings.TrimSpace(v) != "" {
				found = append(found, k)
			}
		}
		if len(found) > 1 {
			return "", "", fmt.Errorf("only one of %s may be set, got %s", strings.Join(sourceKeys, ", "), strings.Join(found, ", "))
		}
		if len(found) == 0 {
			return "", "", nil
		}
		return found[0], strings.TrimSpace(s[found[0]]), nil
	}
	key, val, err := pick(e.per[name])
	if err == nil && key == "" && name != "" {
		key, val, err = pick(e.global)
	}
	if err != nil {
		return err
	}

	switch key {
	case "":
		r.Source = SourcePublic
		return nil
	case "INTERFACE":
		r.Source, r.Interface = SourceInterface, val
		return nil
	case "CUSTOM_LOOKUP_CMD":
		if m := echoRE.FindStringSubmatch(val); m != nil {
			if addr, perr := netip.ParseAddr(m[1]); perr == nil {
				val = addr.String()
				key = "STATIC_IP"
				break
			}
		}
		r.Source, r.LookupCmd = SourceCommand, val
		return nil
	}

	addr, err := netip.ParseAddr(val)
	if err != nil {
		return fmt.Errorf("%s: %q is not an IP address", key, val)
	}
	addr = addr.Unmap()
	if addr.Is6() != r.IPv6() {
		return fmt.Errorf("%s: %s does not match RRTYPE %s", key, addr, r.Type)
	}
	r.Source, r.StaticIP = SourceStatic, addr
	return nil
}

func (e *envSet) globals(cfg *Config) error {
	var errs []error

	spec := strings.TrimSpace(e.vars["CRON"])
	if spec == "" {
		spec = DefaultSchedule
	}
	sched, err := cron.Parse(spec)
	if err != nil {
		errs = append(errs, fmt.Errorf("CRON: %w", err))
	}
	cfg.Schedule = sched

	cfg.Web = Web{Enabled: true, Port: 8080}
	if v := strings.TrimSpace(e.vars["WEB_ENABLED"]); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("WEB_ENABLED: %q is not a boolean", v))
		}
		cfg.Web.Enabled = b
	}
	if v := strings.TrimSpace(e.vars["WEB_PORT"]); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("WEB_PORT: %q is not a valid port", v))
		}
		cfg.Web.Port = p
	}
	cfg.Web.User = strings.TrimSpace(e.vars["WEB_USER"])
	cfg.Web.Password = e.vars["WEB_PASSWORD"]
	if p, ok := e.vars["WEB_PASSWORD_FILE"]; ok && cfg.Web.Password == "" {
		b, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			errs = append(errs, fmt.Errorf("WEB_PASSWORD_FILE: %w", err))
		}
		cfg.Web.Password = strings.TrimSpace(string(b))
	}
	if (cfg.Web.User == "") != (cfg.Web.Password == "") {
		errs = append(errs, errors.New("WEB_USER and WEB_PASSWORD must be set together"))
	}

	if err := e.sync(cfg); err != nil {
		errs = append(errs, err)
	}

	switch strings.ToLower(strings.TrimSpace(e.vars["LOG_LEVEL"])) {
	case "", "info":
		cfg.LogLevel = slog.LevelInfo
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "warn", "warning":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		errs = append(errs, fmt.Errorf("LOG_LEVEL: %q is not one of debug, info, warn, error", e.vars["LOG_LEVEL"]))
	}
	switch f := strings.ToLower(strings.TrimSpace(e.vars["LOG_FORMAT"])); f {
	case "", "text":
		cfg.LogFormat = "text"
	case "json":
		cfg.LogFormat = "json"
	default:
		errs = append(errs, fmt.Errorf("LOG_FORMAT: %q is not text or json", f))
	}

	for _, k := range []string{"PUID", "PGID"} {
		if _, ok := e.vars[k]; ok {
			cfg.Warnings = append(cfg.Warnings, k+" is ignored; set the container user with Docker's user option instead")
		}
	}
	return errors.Join(errs...)
}

// ValidInstanceName reports whether name can label a container.
func ValidInstanceName(name string) bool { return instanceRE.MatchString(name) }

// sync reads SYNC_KEY, SYNC_URL and INSTANCE_NAME. Error messages never
// contain the key.
func (e *envSet) sync(cfg *Config) error {
	var errs []error
	key := e.vars["SYNC_KEY"]
	if p, ok := e.vars["SYNC_KEY_FILE"]; ok && key == "" {
		b, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			errs = append(errs, fmt.Errorf("SYNC_KEY_FILE: %w", err))
		}
		key = string(b)
	}
	key = strings.TrimSpace(key)
	if key != "" && len(key) < MinSyncKeyLength {
		errs = append(errs, fmt.Errorf("SYNC_KEY is too short: use at least %d characters (for example: openssl rand -hex 32)", MinSyncKeyLength))
	}
	cfg.Sync.Key = Secret(key)

	if raw := strings.TrimSpace(e.vars["SYNC_URL"]); raw != "" {
		u, err := url.Parse(raw)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			errs = append(errs, errors.New("SYNC_URL must be an http:// or https:// URL, for example http://ddns:8080"))
		case u.User != nil || u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, errors.New("SYNC_URL must not contain credentials, a query or a fragment"))
		default:
			cfg.Sync.URL = strings.TrimSuffix(u.String(), "/")
		}
		if key == "" {
			errs = append(errs, errors.New("SYNC_URL needs SYNC_KEY, the same key as on the main container"))
		}
	}

	name := strings.ToLower(strings.TrimSpace(e.vars["INSTANCE_NAME"]))
	switch {
	case name == "" && cfg.Sync.Sidecar():
		errs = append(errs, errors.New("INSTANCE_NAME is required with SYNC_URL, so the main container can tell sidecars apart"))
	case name == "":
		name = "main"
	case !ValidInstanceName(name):
		errs = append(errs, fmt.Errorf("INSTANCE_NAME: %q must be 1-63 characters: letters, digits, '.', '_' or '-'", name))
	}
	cfg.Sync.Instance = name

	if cfg.Sync.Main() && !cfg.Web.Enabled {
		errs = append(errs, errors.New("SYNC_KEY without SYNC_URL makes this the main container, which needs WEB_ENABLED=true to receive reports"))
	}
	return errors.Join(errs...)
}
