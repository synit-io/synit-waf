package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIntegration_TenantFeatures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpRoot := t.TempDir()

	upstream := newRecordingUpstream(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-response"))
	})
	defer upstream.Close()

	// Create a custom block page
	blockPagePath := filepath.Join(tmpRoot, "block.html")
	if err := os.WriteFile(blockPagePath, []byte("<html><body><h1>Blocked {{EVENT_ID}}</h1></body></html>"), 0o644); err != nil {
		t.Fatalf("failed to write block page: %v", err)
	}

	// The rate-limited tenant is part of every config below with an unchanged
	// policy, so its limiter must survive the reloads.
	rateLimitTenant := fmt.Sprintf(`  "ratelimit.e2e.local":
    upstreams:
      - url: %q
    security:
      waf_enabled: false
      rate_limit:
        requests_per_minute: 1
        burst: 3
`, upstream.URL)

	// Write the main feature-test configuration.
	configContent := fmt.Sprintf(`global_settings:
  log_level: "info"
  global_rate_limit:
    requests_per_minute: 1000
    burst: 100

waf_rule_sets:
  "base-protection": |
    SecRuleEngine On
    SecRule REQUEST_URI "@contains /never-hit" "id:1,phase:1,deny,status:403"

tenants:
  "features.e2e.local":
    upstreams:
      - url: %q
    header_transform:
      inject_request:
        X-E2E-Test: "verified"
        X-Tenant: "{{TENANT}}"
    security:
      waf_enabled: true
      audit_mode: false
      paranoia_level: 1
      block_page_path: %q
      custom_rules: |
        SecRule ARGS:block "@streq 1" "id:100001,phase:1,deny,status:403"
%s`, upstream.URL, blockPagePath, rateLimitTenant)

	mainConfigPath := writeConfig(t, filepath.Join(tmpRoot, "waf-config", "config.yml"), configContent)
	waf := startWAF(t, mainConfigPath)

	// 1. Verify Proxying, Header Injection & Forwarding Headers
	req := newRequest(t, http.MethodGet, waf.URL+"/", "features.e2e.local", nil)
	// The test client is not a trusted proxy, so its forwarding headers must
	// not reach the upstream, and "Connection" must not strip an injected one.
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("X-Forwarded-Host", "spoofed.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	req.Header.Set("Connection", "X-E2E-Test")
	status, body := sendRequest(t, req)
	if status != http.StatusOK || body != "upstream-response" {
		t.Fatalf("expected proxied 200 response, got %d %q", status, body)
	}
	seen := upstream.last(t)
	for name, want := range map[string]string{
		"X-E2E-Test":        "verified",
		"X-Tenant":          "features.e2e.local",
		"X-Forwarded-For":   "127.0.0.1",
		"X-Forwarded-Host":  "features.e2e.local",
		"X-Forwarded-Proto": "http",
		"X-Real-IP":         "127.0.0.1",
	} {
		if got := strings.Join(seen.Header.Values(name), ", "); got != want {
			t.Errorf("upstream header %s: expected %q, got %q", name, want, got)
		}
	}

	// 2. Verify Per-Tenant Rate Limit
	for i := 1; i <= 3; i++ {
		assertProxyResponse(t, waf.URL, "ratelimit.e2e.local", "/", http.StatusOK, "upstream-response")
	}
	assertProxyResponse(t, waf.URL, "ratelimit.e2e.local", "/", http.StatusTooManyRequests, "Too Many Requests")
	if hits := upstream.hits("ratelimit.e2e.local"); hits != 3 {
		t.Errorf("expected exactly the burst of 3 requests at the upstream, got %d", hits)
	}

	// 3. Verify Custom Block Page
	status, body = sendRequest(t, newRequest(t, http.MethodGet, waf.URL+"/?block=1", "features.e2e.local", nil))
	if status != http.StatusForbidden || !strings.Contains(body, "<h1>Blocked ") {
		t.Fatalf("expected custom block page with 403, got %d %q", status, body)
	}
	if strings.Contains(body, "{{EVENT_ID}}") {
		t.Errorf("block page placeholder was not replaced: %q", body)
	}

	// 4. Verify Metrics Endpoint
	if got := waf.metricValue(t, `synit_waf_http_requests_total{status_class="2xx",tenant="features.e2e.local"}`); got != 1 {
		t.Errorf("expected one 2xx request counted for features.e2e.local, got %v", got)
	}
	if got := waf.metricValue(t, `synit_waf_blocked_requests_total{source="rate_limit",tenant="ratelimit.e2e.local"}`); got != 1 {
		t.Errorf("expected one rate_limit block counted for ratelimit.e2e.local, got %v", got)
	}

	// 5. Verify JWT Validation (after a config reload)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate JWT signing key: %v", err)
	}
	jwks := fmt.Sprintf(`{"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "e2e-key", "x": %q}]}`, base64.RawURLEncoding.EncodeToString(publicKey))
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwks))
	}))
	defer jwksServer.Close()

	jwtConfig := fmt.Sprintf(`global_settings:
  log_level: "info"
waf_rule_sets:
  "base-protection": |
    SecRuleEngine On
tenants:
  "jwt.e2e.local":
    upstreams:
      - url: %q
    security:
      waf_enabled: true
      paranoia_level: 1
      jwt_validation:
        enabled: true
        jwks_endpoint: %q
        issuer: "e2e-issuer"
        audience: "e2e-audience"
%s`, upstream.URL, jwksServer.URL, rateLimitTenant)
	writeConfig(t, mainConfigPath, jwtConfig)
	// Until the reload is published the host is unknown and answers 403.
	waitForProxyStatus(t, waf.URL, "jwt.e2e.local", "/", http.StatusUnauthorized)

	assertProxyResponse(t, waf.URL, "jwt.e2e.local", "/", http.StatusUnauthorized, "Bearer token required")

	sendWithToken := func(claims jwt.MapClaims) (int, string) {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["kid"] = "e2e-key"
		signed, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("failed to sign JWT: %v", err)
		}
		req := newRequest(t, http.MethodGet, waf.URL+"/", "jwt.e2e.local", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		return sendRequest(t, req)
	}
	status, body = sendWithToken(jwt.MapClaims{"iss": "e2e-issuer", "aud": "e2e-audience", "exp": time.Now().Add(time.Hour).Unix()})
	if status != http.StatusOK {
		t.Errorf("expected 200 for a valid JWT, got %d %q", status, body)
	}
	status, body = sendWithToken(jwt.MapClaims{"iss": "e2e-issuer", "aud": "e2e-audience"})
	if status != http.StatusUnauthorized || !strings.Contains(body, "Invalid token") {
		t.Errorf("expected 401 for a JWT without exp, got %d %q", status, body)
	}

	// The reload kept the limiter of the unchanged rate limit policy.
	assertProxyResponse(t, waf.URL, "ratelimit.e2e.local", "/", http.StatusTooManyRequests, "Too Many Requests")

	// 6. Verify Development Bypass (after a config reload)
	const bypassSecret = "e2e-dev-bypass-secret-0123456789abcdef"
	bypassConfig := fmt.Sprintf(`global_settings:
  log_level: "info"
waf_rule_sets:
  "base-protection": |
    SecRuleEngine On
tenants:
  "bypass.e2e.local":
    upstreams:
      - url: %q
    security:
      waf_enabled: true
      paranoia_level: 1
      dev_bypass_secret: %q
      custom_rules: |
        SecRule ARGS:block "@streq 1" "id:100001,phase:1,deny,status:403"
%s`, upstream.URL, bypassSecret, rateLimitTenant)
	writeConfig(t, mainConfigPath, bypassConfig)
	waitForProxyStatus(t, waf.URL, "bypass.e2e.local", "/", http.StatusOK)

	assertProxyResponse(t, waf.URL, "bypass.e2e.local", "/?block=1", http.StatusForbidden, "Forbidden by security policy")

	bypassReq := newRequest(t, http.MethodGet, waf.URL+"/?block=1", "bypass.e2e.local", nil)
	bypassReq.Header.Set("X-Synit-Dev-Bypass", bypassSecret)
	status, body = sendRequest(t, bypassReq)
	if status != http.StatusOK {
		t.Fatalf("bypass failed: status %d, body %q", status, body)
	}
	if leaked := upstream.last(t).Header.Get("X-Synit-Dev-Bypass"); leaked != "" {
		t.Errorf("dev bypass secret was forwarded to the upstream: %q", leaked)
	}

	wrongSecretReq := newRequest(t, http.MethodGet, waf.URL+"/?block=1", "bypass.e2e.local", nil)
	wrongSecretReq.Header.Set("X-Synit-Dev-Bypass", bypassSecret+"x")
	if status, body = sendRequest(t, wrongSecretReq); status != http.StatusForbidden {
		t.Errorf("expected 403 for a wrong bypass secret, got %d %q", status, body)
	}
}
