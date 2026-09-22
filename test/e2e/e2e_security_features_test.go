package tests

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIntegration_SecurityFeatures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Mock Upstream that returns sensitive data and can fail
	var failureMode atomic.Bool
	upstream := newRecordingUpstream(func(w http.ResponseWriter, _ *http.Request) {
		if failureMode.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("upstream-failure"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("My credit card is VISA 4111-1111-1111-1111-1234"))
	})
	defer upstream.Close()

	// WAF Config with IP Sets, Circuit Breaker, and Masking
	configContent := fmt.Sprintf(`global_settings:
  log_level: "info"
  trust_forwarded_for: true
  trusted_proxy_cidrs: ["127.0.0.0/8"]
  ip_sets:
    block_list: ["1.1.1.1/32"]
    allow_list: ["127.0.0.1/32"]

tenants:
  "security.e2e.local":
    upstreams:
      - url: %q
    security:
      waf_enabled: true
      paranoia_level: 1
      circuit_breaker:
        enabled: true
        threshold: 2
        cooldown: "30s"
        failure_status_codes: [503]
      response_masking:
        - pattern: '(?i)VISA \b(?:\d[ -]*?){13,16}\b'
          replacement: "[MASKED_VISA]"
`, upstream.URL)

	waf := startWAF(t, writeConfig(t, filepath.Join(t.TempDir(), "waf-config", "config.yml"), configContent))
	const host = "security.e2e.local"

	// 1. Verify IP Blocking
	req := newRequest(t, http.MethodGet, waf.URL+"/", host, nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	status, body := sendRequest(t, req)
	if status != http.StatusForbidden || !strings.Contains(body, "IP is blocked") {
		t.Fatalf("expected 403 \"IP is blocked\" for blocked IP, got %d %q", status, body)
	}
	if hits := upstream.hits(host); hits != 0 {
		t.Fatalf("request from blocked IP reached the upstream %d time(s)", hits)
	}

	// 2. Verify Forwarding Headers From a Trusted Proxy
	// The test client is inside trusted_proxy_cidrs, so the WAF accepts the
	// client address it reports and passes it on.
	req = newRequest(t, http.MethodGet, waf.URL+"/", host, nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.Header.Set("X-Forwarded-Proto", "https")
	if status, body = sendRequest(t, req); status != http.StatusOK {
		t.Fatalf("expected 200 for request via trusted proxy, got %d %q", status, body)
	}
	seen := upstream.last(t)
	for name, want := range map[string]string{
		"X-Forwarded-For":   "9.9.9.9",
		"X-Real-IP":         "9.9.9.9",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  host,
	} {
		if got := strings.Join(seen.Header.Values(name), ", "); got != want {
			t.Errorf("upstream header %s: expected %q, got %q", name, want, got)
		}
	}

	// 3. Verify Response Masking
	assertProxyResponse(t, waf.URL, host, "/", http.StatusOK, "[MASKED_VISA]")

	// 4. Verify Circuit Breaking
	failureMode.Store(true)
	hitsBefore := upstream.hits(host)
	// Trigger 2 failures; both responses come from the upstream.
	assertProxyResponse(t, waf.URL, host, "/", http.StatusServiceUnavailable, "upstream-failure")
	assertProxyResponse(t, waf.URL, host, "/", http.StatusServiceUnavailable, "upstream-failure")
	if hits := upstream.hits(host) - hitsBefore; hits != 2 {
		t.Fatalf("expected 2 failing requests at the upstream, got %d", hits)
	}

	// The breaker is open now: the WAF answers itself and the upstream is
	// not contacted, even though it has recovered.
	failureMode.Store(false)
	assertProxyResponse(t, waf.URL, host, "/", http.StatusServiceUnavailable, "No healthy upstreams available")
	if hits := upstream.hits(host) - hitsBefore; hits != 2 {
		t.Fatalf("open circuit breaker still let a request through: %d upstream hits, expected 2", hits)
	}
}
