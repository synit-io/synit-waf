package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func writeTenantsConfig(t *testing.T, dir, global, tenants string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	content := "global_settings:\n  log_level: info\n" + global + "\ntenants:\n" + tenants
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func wafTenantYAML(host, upstreamURL, rule string) string {
	return fmt.Sprintf(`  %q:
    upstreams:
      - url: %q
    security:
      waf_enabled: true
      paranoia_level: 1
      custom_rules: |
        %s
`, host, upstreamURL, rule)
}

// A reload must never publish tenants whose upstream health is unknown.
func TestReloadServesTrafficWithoutUnhealthyWindow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	dir := t.TempDir()
	path := writeTenantsConfig(t, dir, "", wafTenantYAML("api.example.com", upstream.URL, `SecRule REQUEST_URI "@contains /blocked" "id:1,phase:1,deny"`))

	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	for round := range 3 {
		if err := h.registry.Reload(path, h); err != nil {
			t.Fatalf("reload %d: %v", round, err)
		}
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/ok", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("reload %d: expected the first request after reload to reach the upstream, got %d", round, w.Code)
		}
	}
}

func TestReloadMarksUnreachableUpstreamBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	path := writeTenantsConfig(t, dir, "", "  \"api.example.com\":\n    upstreams:\n      - url: \"http://127.0.0.1:1\"\n    health_check:\n      timeout: 200ms\n")
	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if report := h.ReadinessReport(); report.Ready {
		t.Fatal("expected readiness to reflect the unreachable upstream immediately after reload")
	}
}

func TestReloadSharesAndReusesWAFInstances(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	rule := `SecRule REQUEST_URI "@contains /blocked" "id:1,phase:1,deny,status:403"`
	tenants := wafTenantYAML("a.example.com", upstream.URL, rule) + wafTenantYAML("b.example.com", upstream.URL, rule) +
		wafTenantYAML("c.example.com", upstream.URL, `SecRule REQUEST_URI "@contains /other" "id:2,phase:1,deny,status:403"`)
	path := writeTenantsConfig(t, dir, "  rules_dir: "+dir, tenants)

	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("reload: %v", err)
	}
	entryA, _, _ := h.registry.Get("a.example.com")
	entryB, _, _ := h.registry.Get("b.example.com")
	entryC, _, _ := h.registry.Get("c.example.com")
	if entryA.WAF != entryB.WAF {
		t.Fatal("expected tenants with identical directives to share one WAF instance")
	}
	if entryA.WAF == entryC.WAF {
		t.Fatal("expected tenants with different directives to have different WAF instances")
	}

	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	reloadedA, _, _ := h.registry.Get("a.example.com")
	if reloadedA.WAF != entryA.WAF {
		t.Fatal("expected an unchanged WAF instance to survive a reload")
	}

	// A changed rule file under rules_dir must invalidate the cache.
	if err := os.WriteFile(filepath.Join(dir, "extra.conf"), []byte("# changed\n"), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("third reload: %v", err)
	}
	rebuiltA, _, _ := h.registry.Get("a.example.com")
	if rebuiltA.WAF == entryA.WAF {
		t.Fatal("expected a rule file change to rebuild the WAF instance")
	}
}

func TestReloadKeepsRateLimitersWhenPolicyIsUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	tenant := fmt.Sprintf("  \"api.example.com\":\n    upstreams:\n      - url: %q\n    security:\n      rate_limit:\n        requests_per_minute: 1\n        burst: 1\n", upstream.URL)
	path := writeTenantsConfig(t, dir, "", tenant)
	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("reload: %v", err)
	}
	policy := RateLimitPolicy{RequestsPerMinute: 1, Burst: 1}
	if !h.allowRateLimitedRequest("api.example.com", "192.0.2.1", policy) {
		t.Fatal("expected the first request to pass")
	}
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	if h.allowRateLimitedRequest("api.example.com", "192.0.2.1", policy) {
		t.Fatal("expected a reload not to reset the client's rate limit")
	}
}

func TestLoadConfigBodyLimitAliasAndPrecedence(t *testing.T) {
	upstreamTenant := "  \"api.example.com\":\n    upstreams:\n      - url: \"http://127.0.0.1:9\"\n"
	dir := t.TempDir()

	path := writeTenantsConfig(t, dir, "  response_buffer_limit: 4096", upstreamTenant)
	cfg, err := LoadConfig(path)
	if err != nil || cfg.GlobalSettings.RequestBodyLimit != 4096 {
		t.Fatalf("expected the deprecated key to set the request body limit, got %d, %v", cfg.GlobalSettings.RequestBodyLimit, err)
	}

	t.Setenv("WAF_GLOBAL_REQUEST_BODY_LIMIT", "8192")
	cfg, err = LoadConfig(path)
	if err != nil || cfg.GlobalSettings.RequestBodyLimit != 8192 {
		t.Fatalf("expected the environment to win over the file, got %d, %v", cfg.GlobalSettings.RequestBodyLimit, err)
	}
	t.Setenv("WAF_GLOBAL_REQUEST_BODY_LIMIT", "")

	path = writeTenantsConfig(t, dir, "  response_buffer_limit: 4096\n  request_body_limit: 1024", upstreamTenant)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected conflicting old and new keys to be rejected")
	}
}

func TestSecretEnvReadsFileVariant(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	t.Setenv("SYNIT_TEST_SECRET_FILE", secretFile)
	if got, err := secretEnv("SYNIT_TEST_SECRET"); err != nil || got != "from-file" {
		t.Fatalf("expected the file value, got %q, %v", got, err)
	}
	t.Setenv("SYNIT_TEST_SECRET", "from-env")
	if got, _ := secretEnv("SYNIT_TEST_SECRET"); got != "from-env" {
		t.Fatalf("expected the plain variable to win, got %q", got)
	}
	t.Setenv("SYNIT_TEST_SECRET", "")
	t.Setenv("SYNIT_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := secretEnv("SYNIT_TEST_SECRET"); err == nil {
		t.Fatal("expected a missing secret file to be an error")
	}
}

func TestValidateConfigNewInvariants(t *testing.T) {
	mutate := func(change func(*AppConfig, *Tenant)) error {
		cfg := baseValidConfig()
		tenant := cfg.Tenants["api.example.com"]
		change(&cfg, &tenant)
		cfg.Tenants["api.example.com"] = tenant
		return ValidateConfig(cfg)
	}
	cases := map[string]func(*AppConfig, *Tenant){
		"acme without agree_tos": func(cfg *AppConfig, _ *Tenant) {
			cfg.GlobalSettings.ACME.Enabled = true
			cfg.GlobalSettings.ACME.Email = "ops@example.com"
		},
		"short dev bypass secret": func(_ *AppConfig, tenant *Tenant) { tenant.Security.DevBypassSecret = "short" },
		"jwt with basic auth": func(_ *AppConfig, tenant *Tenant) {
			tenant.Security.JWTValidation = JWTValidationConfig{Enabled: true, JWKSEndpoint: "https://keys.example.com/jwks", Issuer: "i", Audience: "a"}
			tenant.Security.BasicAuth = []BasicAuthCredentials{{User: "u", Password: "$2a$04$abcdefghijklmnopqrstuuJ6mP9WcYyG3n7o4mXxJ2T8m1rYk0p8y"}}
		},
		"graphql path without slash": func(_ *AppConfig, tenant *Tenant) {
			tenant.Security.GraphQL = GraphQLProtection{Enabled: true, Paths: []string{"graphql"}}
		},
		"llm path with quote": func(_ *AppConfig, tenant *Tenant) {
			tenant.Security.LLMProtection.InspectPaths = []string{`/v1/"chat`}
		},
		"missing block page": func(_ *AppConfig, tenant *Tenant) {
			tenant.Security.BlockPagePath = filepath.Join(os.TempDir(), "synit-waf-missing-block-page.html")
		},
		"negative health check": func(_ *AppConfig, tenant *Tenant) { tenant.HealthCheck.Interval = -time.Second },
		"negative crowdsec cache ttl": func(cfg *AppConfig, _ *Tenant) {
			ttl := -time.Second
			cfg.CrowdSec.CacheTTL = &ttl
		},
	}
	for name, change := range cases {
		if err := mutate(change); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	if err := mutate(func(cfg *AppConfig, _ *Tenant) {
		cfg.GlobalSettings.ACME.Enabled = true
		cfg.GlobalSettings.ACME.Email = "ops@example.com"
		cfg.GlobalSettings.ACME.AgreeTOS = true
	}); err != nil {
		t.Errorf("expected ACME with agree_tos to validate, got %v", err)
	}
}

func TestHTTPHealthCheckUsesConfiguredPath(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	var paths atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths.Store(r.URL.Path)
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer upstream.Close()

	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	tenant := Tenant{Upstreams: []Upstream{{URL: upstream.URL}}, HealthCheck: HealthCheckConfig{Path: "/ready", Timeout: time.Second}}
	state, err := h.buildTenantState("api.example.com", tenant)
	if err != nil {
		t.Fatalf("build tenant state: %v", err)
	}
	h.performCheck(state.upstreams[0])
	if !state.upstreams[0].isHealthy.Load() || paths.Load() != "/ready" {
		t.Fatalf("expected a healthy HTTP check on /ready, got path %v", paths.Load())
	}
	healthy.Store(false)
	h.performCheck(state.upstreams[0])
	if state.upstreams[0].isHealthy.Load() {
		t.Fatal("expected a 503 health response to mark the upstream unhealthy")
	}
}

func TestCrowdSecDecisionsAreCached(t *testing.T) {
	var calls atomic.Int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "203.0.113.66") {
			_, _ = w.Write([]byte(`[{"duration":"1h","origin":"cscli","scenario":"test","scope":"Ip","type":"ban","value":"203.0.113.66"}]`))
			return
		}
		_, _ = w.Write([]byte("null"))
	}))
	defer lapi.Close()
	bouncer := &csbouncer.LiveBouncer{APIKey: "key", APIUrl: lapi.URL + "/"}
	if err := bouncer.Init(); err != nil {
		t.Fatalf("init bouncer: %v", err)
	}

	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	for range 3 {
		banned, err := h.crowdSecBanned(t.Context(), bouncer, "203.0.113.66")
		if err != nil || !banned {
			t.Fatalf("expected a banned verdict, got %v, %v", banned, err)
		}
		clean, err := h.crowdSecBanned(t.Context(), bouncer, "198.51.100.1")
		if err != nil || clean {
			t.Fatalf("expected a clean verdict, got %v, %v", clean, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected one LAPI call per address, got %d", got)
	}

	h.crowdsecCacheTTL.Store(0)
	if _, err := h.crowdSecBanned(t.Context(), bouncer, "198.51.100.1"); err != nil {
		t.Fatalf("uncached lookup: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected a disabled cache to query LAPI, got %d calls", got)
	}
}
