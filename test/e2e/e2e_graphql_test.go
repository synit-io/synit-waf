package tests

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegration_GraphQLProtection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	upstream := newRecordingUpstream(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": {"user": {"id": 1}}}`))
	})
	defer upstream.Close()

	configContent := fmt.Sprintf(`global_settings:
  log_level: "info"

tenants:
  "graphql.e2e.local":
    upstreams:
      - url: %q
    security:
      waf_enabled: true
      paranoia_level: 1
      graphql:
        enabled: true
        block_introspection: true
        max_query_depth: 3
        max_batched_queries: 2
`, upstream.URL)

	waf := startWAF(t, writeConfig(t, filepath.Join(t.TempDir(), "waf-config", "config.yml"), configContent))
	const host = "graphql.e2e.local"

	sendGraphQL := func(payload string) (int, string) {
		req := newRequest(t, http.MethodPost, waf.URL+"/graphql", host, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		return sendRequest(t, req)
	}

	// 1. Valid Query
	status, _ := sendGraphQL(`{"query": "{ user { id } }"}`)
	if status != http.StatusOK {
		t.Errorf("Expected 200 OK for valid query, got %d", status)
	}

	// 2. Introspection Query
	status, body := sendGraphQL(`{"query": "{ __schema { types { name } } }"}`)
	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for introspection query, got %d", status)
	}
	if !strings.Contains(body, "introspection queries are not allowed") {
		t.Errorf("Expected introspection error message, got: %s", body)
	}

	// 3. Max Depth Exceeded (limit is 3)
	// Depth: { user(1) { friends(2) { friends(3) { id(4) } } } } -> 4
	status, body = sendGraphQL(`{"query": "{ user { friends { friends { id } } } }"}`)
	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for deep query, got %d", status)
	}
	if !strings.Contains(body, "depth exceeds maximum allowed limit") {
		t.Errorf("Expected depth limit error message, got: %s", body)
	}

	// 4. Batching Limit Exceeded (limit is 2)
	status, body = sendGraphQL(`[
		{"query": "{ user { id } }"},
		{"query": "{ user { name } }"},
		{"query": "{ user { email } }"}
	]`)
	if status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for excessive batch, got %d", status)
	}
	if !strings.Contains(body, "batch size exceeds maximum allowed limit") {
		t.Errorf("Expected batch limit error message, got: %s", body)
	}

	// 5. Other Paths of the Tenant
	// GraphQL protection covers graphql.paths only (default "/graphql"). The
	// same requests on /graphql would be answered 400 and 415 by the WAF.
	hitsBefore := upstream.hits(host)
	assertProxyResponse(t, waf.URL, host, "/", http.StatusOK, `"data"`)

	formReq := newRequest(t, http.MethodPost, waf.URL+"/api/login", host, strings.NewReader("user=alice"))
	formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if status, body = sendRequest(t, formReq); status != http.StatusOK {
		t.Errorf("Expected 200 OK for form POST outside graphql.paths, got %d. Body: %s", status, body)
	}
	if hits := upstream.hits(host) - hitsBefore; hits != 2 {
		t.Errorf("Expected both non-GraphQL requests at the upstream, got %d", hits)
	}

	status, _ = sendRequest(t, newRequest(t, http.MethodGet, waf.URL+"/graphql", host, nil))
	if status != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for GET /graphql without query, got %d", status)
	}
	formReq = newRequest(t, http.MethodPost, waf.URL+"/graphql", host, strings.NewReader("user=alice"))
	formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if status, _ = sendRequest(t, formReq); status != http.StatusUnsupportedMediaType {
		t.Errorf("Expected 415 Unsupported Media Type for form POST on /graphql, got %d", status)
	}
}
