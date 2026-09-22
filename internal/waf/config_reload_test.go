package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeReloadConfig(t *testing.T, dir, upstreamURL, global, customRules string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	content := fmt.Sprintf(`global_settings:
  request_body_limit: 1024
%s
tenants:
  "api.example.com":
    upstreams:
      - url: %q
    security:
      waf_enabled: true
      paranoia_level: 1
      custom_rules: |
        %s
`, global, upstreamURL, customRules)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestReloadRejectsUnknownYAMLField(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	path := writeReloadConfig(t, dir, upstream.URL, "  unknown_security_setting: true", "SecRuleEngine On")

	h := NewProxyHandler(NewWAFRegistry())
	if err := h.registry.Reload(path, h); err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
}

func TestReloadRejectsInvalidShard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	path := writeReloadConfig(t, dir, upstream.URL, "", "SecRuleEngine On")
	shardDir := filepath.Join(dir, "tenants.d")
	if err := os.Mkdir(shardDir, 0o700); err != nil {
		t.Fatalf("create shard directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shardDir, "broken.yml"), []byte("tenants: ["), 0o600); err != nil {
		t.Fatalf("write shard: %v", err)
	}

	h := NewProxyHandler(NewWAFRegistry())
	if err := h.registry.Reload(path, h); err == nil {
		t.Fatal("expected invalid shard to reject reload")
	}
}

func TestReloadAppliesEnvironmentOverrides(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	t.Setenv("WAF_GLOBAL_RESPONSE_BUFFER_LIMIT", "2048")
	dir := t.TempDir()
	path := writeReloadConfig(t, dir, upstream.URL, "", "SecRuleEngine On")

	h := NewProxyHandler(NewWAFRegistry())
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := h.requestBodyLimit.Load(); got != 2048 {
		t.Fatalf("expected environment override 2048, got %d", got)
	}
}

func TestLoadConfigResolvesLLMSidecarTokenEnvironment(t *testing.T) {
	t.Setenv("TEST_LLM_TOKEN", "secret-token")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := `tenants:
  "api.example.com":
    upstreams:
      - url: "http://localhost:8080"
    security:
      waf_enabled: false
      llm_protection:
        enabled: true
        mode: "ml"
        sidecar_url: "http://localhost:5001/v1/detect"
        sidecar_token_env: "TEST_LLM_TOKEN"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got := cfg.Tenants["api.example.com"].Security.LLMProtection.SidecarToken; got != "secret-token" {
		t.Fatalf("expected resolved token, got %q", got)
	}
}

func TestFailedReloadDoesNotMutateRuntime(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	path := writeReloadConfig(t, dir, upstream.URL, "  global_rate_limit:\n    requests_per_minute: 60\n    burst: 1", "SecRuleEngine On")

	h := NewProxyHandler(NewWAFRegistry())
	if err := h.registry.Reload(path, h); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	originalLimiter := h.globalLimiter.Load()

	writeReloadConfig(t, dir, upstream.URL, "  global_rate_limit:\n    requests_per_minute: 120\n    burst: 2", `SecRule BROKEN`)
	if err := h.registry.Reload(path, h); err == nil {
		t.Fatal("expected invalid WAF rules to reject reload")
	}
	if h.globalLimiter.Load() != originalLimiter {
		t.Fatal("failed reload replaced active global limiter")
	}
}

func TestReloadReusesUnchangedCoordinatorLeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	caFile, certFile, keyFile := writeCoordinatorTestCertificates(t)
	dir := t.TempDir()
	global := fmt.Sprintf(`  coordinator:
    enabled: true
    role: leader
    address: "127.0.0.1:0"
    secret: "test-secret"
    tls:
      ca_file: %q
      cert_file: %q
      key_file: %q`, caFile, certFile, keyFile)
	path := writeReloadConfig(t, dir, upstream.URL, global, "SecRuleEngine On")

	registry := NewWAFRegistry()
	h := NewProxyHandler(registry)
	t.Cleanup(func() { _ = h.Close() })
	if err := registry.Reload(path, h); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	first := h.coordinator.Load()
	if first == nil {
		t.Fatal("expected coordinator after initial reload")
	}
	if err := registry.Reload(path, h); err != nil {
		t.Fatalf("unchanged reload: %v", err)
	}
	if got := h.coordinator.Load(); got != first {
		t.Fatal("expected unchanged coordinator to be reused")
	}
}
