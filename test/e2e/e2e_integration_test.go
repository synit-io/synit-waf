package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestIntegration_WAF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// The upstream echoes the path so a proxied response is distinguishable
	// from the WAF's own "ok" liveness answer.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("upstream-ok " + r.URL.Path))
	}))
	defer upstream.Close()

	waf := startWAF(t, writeIntegrationConfig(t, upstream.URL))

	t.Run("routing and blocking", func(t *testing.T) {
		assertProxyResponse(t, waf.URL, "tenant.example.local", "/allowed", http.StatusOK, "upstream-ok /allowed")
		assertProxyResponse(t, waf.URL, "unknown.example.local", "/allowed", http.StatusForbidden, "Forbidden")
		assertProxyResponse(t, waf.URL, "tenant.example.local", "/blocked", http.StatusForbidden, "")
	})

	t.Run("liveness and admin endpoints", func(t *testing.T) {
		// The public listener answers liveness probes only for hosts that are
		// not tenants, such as the address a probe uses.
		for _, path := range []string{"/livez", "/healthz"} {
			status, body := sendRequest(t, newRequest(t, http.MethodGet, waf.URL+path, "", nil))
			if status != http.StatusOK || body != "ok" {
				t.Errorf("public %s without tenant host: expected 200 \"ok\", got %d %q", path, status, body)
			}
			// For a tenant host the path belongs to the application.
			assertProxyResponse(t, waf.URL, "tenant.example.local", path, http.StatusOK, "upstream-ok "+path)
		}

		// Operational endpoints exist only on the admin listener.
		for _, path := range []string{"/livez", "/healthz", "/readyz", "/metrics"} {
			assertProxyResponse(t, waf.AdminURL, "", path, http.StatusOK, "")
		}
		for _, path := range []string{"/readyz", "/metrics"} {
			assertProxyResponse(t, waf.URL, "", path, http.StatusForbidden, "")
			assertProxyResponse(t, waf.URL, "tenant.example.local", path, http.StatusOK, "upstream-ok "+path)
		}
	})

	t.Run("phase 2 rule blocks a request without body", func(t *testing.T) {
		assertProxyResponse(t, waf.URL, "tenant.example.local", "/allowed?probe=harmless", http.StatusOK, "upstream-ok /allowed")
		assertProxyResponse(t, waf.URL, "tenant.example.local", "/allowed?probe=phase2", http.StatusForbidden, "Forbidden by security policy")
		waf.waitForLog(t, "WAF rule matched", "rule_id=100002", "host=tenant.example.local", "audit_mode=false")
	})

	t.Run("audit mode detects without blocking", func(t *testing.T) {
		const series = `synit_waf_audit_mode_events_total{tenant="audit.example.local"}`
		before := waf.metricValue(t, series)

		assertProxyResponse(t, waf.URL, "audit.example.local", "/allowed?probe=harmless", http.StatusOK, "upstream-ok /allowed")
		if got := waf.metricValue(t, series); got != before {
			t.Errorf("%s changed from %v to %v for a harmless request", series, before, got)
		}

		assertProxyResponse(t, waf.URL, "audit.example.local", "/allowed?probe=phase2", http.StatusOK, "upstream-ok /allowed")
		if got := waf.metricValue(t, series); got != before+1 {
			t.Errorf("%s: expected %v after one detection, got %v", series, before+1, got)
		}
		waf.waitForLog(t, "WAF rule matched", "rule_id=100002", "host=audit.example.local", "audit_mode=true")
		waf.waitForLog(t, "WAF attack detected (Audit Mode)", "rule_id=100002", "tenant=audit.example.local")
	})
}

func writeIntegrationConfig(t *testing.T, upstreamURL string) string {
	t.Helper()

	// Both tenants carry the same rules; only audit_mode differs. Rule 100002
	// runs in phase 2, which the WAF must also evaluate for a bodiless GET.
	const rules = `
        SecRule REQUEST_URI "@contains /blocked" "id:100001,phase:1,deny,status:403,msg:'blocked-by-integration-test'"
        SecRule ARGS:probe "@streq phase2" "id:100002,phase:2,deny,status:403,log,msg:'phase2-blocked-by-integration-test'"`

	content := fmt.Sprintf(`global_settings:
  log_level: "info"

tenants:
  "tenant.example.local":
    upstreams:
      - url: %[1]q
    security:
      waf_enabled: true
      paranoia_level: 1
      custom_rules: |%[2]s
  "audit.example.local":
    upstreams:
      - url: %[1]q
    security:
      waf_enabled: true
      audit_mode: true
      paranoia_level: 1
      custom_rules: |%[2]s
`, upstreamURL, rules)

	return writeConfig(t, filepath.Join(t.TempDir(), "integration-config.yml"), content)
}
