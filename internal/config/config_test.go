package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, env ...string) *Config {
	t.Helper()
	cfg, err := Load(env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func loadErr(t *testing.T, want string, env ...string) {
	t.Helper()
	_, err := Load(env)
	if err == nil {
		t.Fatalf("Load succeeded, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

func TestSingleRecordOznuCompatible(t *testing.T) {
	cfg := load(t, "API_KEY=tok", "ZONE=Example.COM.", "SUBDOMAIN=www", "PROXIED=true")
	if len(cfg.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(cfg.Records))
	}
	r := cfg.Records[0]
	if r.Name != "default" || r.FQDN() != "www.example.com" || r.Type != "A" || !r.Proxied || r.Source != SourcePublic {
		t.Fatalf("unexpected record %+v", r)
	}
	if r.Credentials.Token != "tok" || r.Credentials.Kind() != "api-token" {
		t.Fatalf("unexpected credentials kind %s", r.Credentials.Kind())
	}
	if cfg.Schedule.String() != DefaultSchedule || !cfg.Web.Enabled || cfg.Web.Port != 8080 {
		t.Fatalf("unexpected defaults: %s %+v", cfg.Schedule, cfg.Web)
	}
}

func TestApexRecord(t *testing.T) {
	cfg := load(t, "API_KEY=tok", "ZONE=example.com")
	if got := cfg.Records[0].FQDN(); got != "example.com" {
		t.Fatalf("FQDN = %q", got)
	}
	cfg = load(t, "API_KEY=tok", "ZONE_ROOT=example.com", "SUBDOMAIN_ROOT=@")
	if got := cfg.Records[0].FQDN(); got != "example.com" {
		t.Fatalf("FQDN = %q", got)
	}
}

func TestSuffixedRecordsWithDefaults(t *testing.T) {
	cfg := load(t,
		"API_KEY=shared", "ZONE=example.com", "PROXIED=true",
		"SUBDOMAIN_BLOG=blog",
		"SUBDOMAIN_SHOP=shop", "PROXIED_SHOP=false",
		"ZONE_OTHER=example.org", "SUBDOMAIN_OTHER=imp", "API_KEY_OTHER=other",
		"CUSTOM_LOOKUP_CMD_OTHER=echo 192.0.2.10",
		"PATH=/usr/bin", "HOSTNAME=abc",
	)
	if len(cfg.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(cfg.Records))
	}
	byName := map[string]Record{}
	for _, r := range cfg.Records {
		byName[r.Name] = r
	}
	if r := byName["blog"]; r.FQDN() != "blog.example.com" || !r.Proxied || r.Credentials.Token != "shared" {
		t.Fatalf("blog = %+v", r)
	}
	if r := byName["shop"]; r.Proxied {
		t.Fatalf("shop should not be proxied: %+v", r)
	}
	r := byName["other"]
	if r.FQDN() != "imp.example.org" || r.Credentials.Token != "other" || r.Source != SourceStatic || r.StaticIP.String() != "192.0.2.10" {
		t.Fatalf("other = %+v", r)
	}
	if cfg.Records[0].Name != "blog" || cfg.Records[2].Name != "shop" {
		t.Fatalf("records not sorted by name: %s, %s", cfg.Records[0].Name, cfg.Records[2].Name)
	}
}

func TestIPSources(t *testing.T) {
	cfg := load(t, "API_KEY=t", "ZONE=example.com",
		"SUBDOMAIN_A=a", "STATIC_IP_A=192.0.2.1",
		"SUBDOMAIN_B=b", "CUSTOM_LOOKUP_CMD_B=curl -s https://ip.example",
		"SUBDOMAIN_C=c", "INTERFACE_C=eth0",
		"SUBDOMAIN_D=d", "RRTYPE_D=aaaa", "STATIC_IP_D=2001:db8::1",
		"SUBDOMAIN_E=e", `CUSTOM_LOOKUP_CMD_E=echo "192.0.2.5"`,
	)
	want := map[string]Source{"a": SourceStatic, "b": SourceCommand, "c": SourceInterface, "d": SourceStatic, "e": SourceStatic}
	for _, r := range cfg.Records {
		if r.Source != want[r.Name] {
			t.Errorf("%s: source = %s, want %s", r.Name, r.Source, want[r.Name])
		}
	}
	if cfg.Records[3].Type != "AAAA" {
		t.Errorf("d: type = %s", cfg.Records[3].Type)
	}
}

func TestPerRecordSourceOverridesDefault(t *testing.T) {
	cfg := load(t, "API_KEY=t", "ZONE=example.com", "STATIC_IP=192.0.2.1",
		"SUBDOMAIN_A=a", "SUBDOMAIN_B=b", "INTERFACE_B=eth0")
	if cfg.Records[0].Source != SourceStatic || cfg.Records[1].Source != SourceInterface {
		t.Fatalf("sources = %s, %s", cfg.Records[0].Source, cfg.Records[1].Source)
	}
}

func TestFileVariables(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := load(t, "API_KEY_FILE="+tok, "ZONE=example.com", "SUBDOMAIN_X=x", "API_KEY_FILE_Y="+tok, "SUBDOMAIN_Y=y")
	for _, r := range cfg.Records {
		if r.Credentials.Token != "secret-token" {
			t.Fatalf("%s: token not read from file", r.Name)
		}
	}
	loadErr(t, "API_KEY_FILE", "API_KEY_FILE="+filepath.Join(dir, "missing"), "ZONE=example.com")
}

func TestGlobalAPIKeyWithEmail(t *testing.T) {
	cfg := load(t, "API_KEY=k", "EMAIL=ops@example.com", "ZONE=example.com")
	if cfg.Records[0].Credentials.Kind() != "global-api-key" {
		t.Fatal("expected global API key credentials")
	}
	if s := cfg.Records[0].Credentials.String(); strings.Contains(s, "k") && !strings.Contains(s, "redacted") {
		t.Fatalf("credentials leak in String(): %s", s)
	}
}

func TestCredentialsNeverPrinted(t *testing.T) {
	c := Credentials{Token: "super-secret"}
	if strings.Contains(c.String(), "super-secret") || strings.Contains(c.LogValue().String(), "super-secret") {
		t.Fatal("credentials leaked")
	}
}

func TestWebAndLogSettings(t *testing.T) {
	cfg := load(t, "API_KEY=t", "ZONE=example.com", "WEB_ENABLED=false", "WEB_PORT=9000",
		"WEB_USER=admin", "WEB_PASSWORD=pw", "LOG_LEVEL=debug", "LOG_FORMAT=json", "CRON=@hourly", "PUID=1000")
	if cfg.Web.Enabled || cfg.Web.Port != 9000 || cfg.Web.User != "admin" || cfg.LogFormat != "json" || cfg.Schedule.String() != "@hourly" {
		t.Fatalf("unexpected config %+v", cfg)
	}
	if len(cfg.Warnings) != 1 {
		t.Fatalf("warnings = %v", cfg.Warnings)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		name string
		want string
		env  []string
	}{
		{"no records", "no records configured", []string{"API_KEY=t"}},
		{"no token", "API_KEY is empty", []string{"ZONE=example.com"}},
		{"typo in suffix", "record BOLG", []string{"API_KEY=t", "ZONE=example.com", "SUBDOMAIN_BLOG=b", "PROXIED_BOLG=true"}},
		{"mixed subdomain", "SUBDOMAIN without a suffix", []string{"API_KEY=t", "ZONE=example.com", "SUBDOMAIN=www", "SUBDOMAIN_B=b"}},
		{"duplicate", "both manage", []string{"API_KEY=t", "ZONE=example.com", "SUBDOMAIN_A=x", "SUBDOMAIN_B=x"}},
		{"bad bool", "not a boolean", []string{"API_KEY=t", "ZONE=example.com", "PROXIED=yes please"}},
		{"bad rrtype", "RRTYPE", []string{"API_KEY=t", "ZONE=example.com", "RRTYPE=CNAME"}},
		{"family mismatch", "does not match", []string{"API_KEY=t", "ZONE=example.com", "STATIC_IP=2001:db8::1"}},
		{"two sources", "only one of", []string{"API_KEY=t", "ZONE=example.com", "STATIC_IP=192.0.2.1", "INTERFACE=eth0"}},
		{"bad cron", "CRON", []string{"API_KEY=t", "ZONE=example.com", "CRON=every five minutes"}},
		{"half auth", "WEB_USER and WEB_PASSWORD", []string{"API_KEY=t", "ZONE=example.com", "WEB_USER=admin"}},
		{"bad port", "WEB_PORT", []string{"API_KEY=t", "ZONE=example.com", "WEB_PORT=70000"}},
		{"bad level", "LOG_LEVEL", []string{"API_KEY=t", "ZONE=example.com", "LOG_LEVEL=loud"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { loadErr(t, tc.want, tc.env...) })
	}
}

func TestErrorsDoNotLeakToken(t *testing.T) {
	_, err := Load([]string{"API_KEY=very-secret-token", "ZONE=example.com", "PROXIED=maybe"})
	if err == nil || strings.Contains(err.Error(), "very-secret-token") {
		t.Fatalf("error leaks token or is nil: %v", err)
	}
}

const testSyncKey = "0123456789abcdef0123456789abcdef-sync"

func TestSyncDefaultsToStandalone(t *testing.T) {
	cfg := load(t, "API_KEY=tok", "ZONE=example.com")
	if cfg.Sync.Main() || cfg.Sync.Sidecar() || cfg.Sync.Instance != "main" {
		t.Fatalf("sync = %+v", cfg.Sync)
	}
}

func TestSyncMainAndSidecar(t *testing.T) {
	main := load(t, "API_KEY=tok", "ZONE=example.com", "SYNC_KEY="+testSyncKey, "INSTANCE_NAME=Home")
	if !main.Sync.Main() || main.Sync.Sidecar() || main.Sync.Instance != "home" {
		t.Fatalf("main = %+v", main.Sync)
	}
	side := load(t, "API_KEY=tok", "ZONE=example.org", "SYNC_KEY="+testSyncKey,
		"SYNC_URL=http://ddns:8080/", "INSTANCE_NAME=org")
	if side.Sync.Main() || !side.Sync.Sidecar() || side.Sync.URL != "http://ddns:8080" {
		t.Fatalf("sidecar = %+v", side.Sync)
	}
}

func TestSyncKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(testSyncKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := load(t, "API_KEY=tok", "ZONE=example.com", "SYNC_KEY_FILE="+p)
	if string(cfg.Sync.Key) != testSyncKey {
		t.Fatal("SYNC_KEY_FILE not read")
	}
}

func TestSyncErrorsNeverContainTheKey(t *testing.T) {
	short := "short-secret-value"
	cases := []struct {
		want string
		env  []string
	}{
		{"too short", []string{"SYNC_KEY=" + short}},
		{"SYNC_URL needs SYNC_KEY", []string{"SYNC_URL=http://ddns:8080", "INSTANCE_NAME=x"}},
		{"http:// or https://", []string{"SYNC_KEY=" + testSyncKey, "SYNC_URL=ftp://ddns", "INSTANCE_NAME=x"}},
		{"must not contain credentials", []string{"SYNC_KEY=" + testSyncKey, "SYNC_URL=http://u:p@ddns:8080", "INSTANCE_NAME=x"}},
		{"INSTANCE_NAME is required", []string{"SYNC_KEY=" + testSyncKey, "SYNC_URL=http://ddns:8080"}},
		{"INSTANCE_NAME", []string{"INSTANCE_NAME=bad name"}},
		{"WEB_ENABLED=true", []string{"SYNC_KEY=" + testSyncKey, "WEB_ENABLED=false"}},
	}
	for _, c := range cases {
		env := append([]string{"API_KEY=tok", "ZONE=example.com"}, c.env...)
		_, err := Load(env)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: error = %v, want %q", c.env, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), short) || strings.Contains(err.Error(), testSyncKey) {
			t.Errorf("%v: error leaks the key: %v", c.env, err)
		}
	}
}

func TestSecretRedacts(t *testing.T) {
	s := Secret(testSyncKey)
	if strings.Contains(s.String(), testSyncKey) || strings.Contains(s.LogValue().String(), testSyncKey) {
		t.Fatal("secret printed")
	}
}
