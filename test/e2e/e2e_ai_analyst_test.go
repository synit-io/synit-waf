package tests

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegration_AILogsReceiver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpRoot := t.TempDir()
	logsDir := filepath.Join(tmpRoot, "ai-logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}
	tenantID := "ai-test"
	// The receiver requires tokens of at least 32 characters.
	token := "ai-test-token-0123456789abcdef0123456789"
	tenantLogsDir := filepath.Join(logsDir, tenantID)

	receiverURL := startAILogsReceiverProcess(t, tenantID, token, logsDir)

	postLogs := func(bearer, contentType, payload string) (int, string) {
		req := newRequest(t, http.MethodPost, receiverURL+"/logs", "", strings.NewReader(payload))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		return sendRequest(t, req)
	}
	// Failed authentications are throttled per client IP, and every client in
	// this test is 127.0.0.1, so they are counted.
	authFailures := 0

	// 1. Verify log reception: single JSON line and NDJSON batch.
	logPayload := `{"event": "test-log", "tenant": "ai.test"}`
	if status, body := postLogs(token, "application/json", logPayload); status != http.StatusOK {
		t.Fatalf("Log export failed: status %d, body %q", status, body)
	}
	batchPayload := `{"event": "batch-1"}` + "\n" + `{"event": "batch-2"}` + "\n"
	if status, body := postLogs(token, "application/x-ndjson", batchPayload); status != http.StatusOK {
		t.Fatalf("NDJSON log export failed: status %d, body %q", status, body)
	}

	// Verify the lines exist on disk
	stored := readTenantLogs(t, tenantLogsDir)
	for _, line := range []string{logPayload, `{"event": "batch-1"}`, `{"event": "batch-2"}`} {
		if !strings.Contains(stored, line+"\n") {
			t.Errorf("Log file does not contain line %s, got:\n%s", line, stored)
		}
	}

	// 2. Verify request validation.
	if status, _ := postLogs(token, "", logPayload); status != http.StatusUnsupportedMediaType {
		t.Errorf("Expected 415 without Content-Type, got %d", status)
	}
	if status, _ := postLogs(token, "application/json", "not json"); status != http.StatusBadRequest {
		t.Errorf("Expected 400 for a non-JSON line, got %d", status)
	}
	if status, _ := postLogs(token, "application/json", batchPayload); status != http.StatusBadRequest {
		t.Errorf("Expected 400 for several lines sent as application/json, got %d", status)
	}
	if status, _ := postLogs("invalid-token", "application/json", logPayload); status != http.StatusForbidden {
		t.Errorf("Expected 403 for invalid token, got %d", status)
	}
	authFailures++
	if status, _ := postLogs("", "application/json", logPayload); status != http.StatusUnauthorized {
		t.Errorf("Expected 401 without token, got %d", status)
	}
	authFailures++

	// 3. Verify WAF log forwarding into the receiver.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	configContent := fmt.Sprintf(`global_settings:
  log_level: "info"

logging:
  log_forwarder:
    enabled: true
    url: %q
    token: %q

tenants:
  "ai.e2e.local":
    upstreams:
      - url: %q
    security:
      waf_enabled: false
`, receiverURL+"/logs", token, upstream.URL)
	waf := startWAF(t, writeConfig(t, filepath.Join(tmpRoot, "waf-config", "config.yml"), configContent))

	assertProxyResponse(t, waf.URL, "ai.e2e.local", "/forwarded-by-waf", http.StatusOK, "upstream-ok")

	// The forwarder sends NDJSON batches every 250ms, so the event arrives
	// shortly after the response.
	waitFor(t, stateChangeTimeout, "the forwarded access log event in "+tenantLogsDir, func() error {
		for line := range strings.SplitSeq(readTenantLogs(t, tenantLogsDir), "\n") {
			var event struct {
				Message string `json:"message"`
				Tenant  string `json:"tenant"`
				Method  string `json:"method"`
				Path    string `json:"path"`
				Status  int    `json:"status"`
			}
			if line == "" || json.Unmarshal([]byte(line), &event) != nil {
				continue
			}
			if event.Message == "request handled" && event.Tenant == "ai.e2e.local" && event.Method == http.MethodGet &&
				event.Path == "/forwarded-by-waf" && event.Status == http.StatusOK {
				return nil
			}
		}
		return fmt.Errorf("no matching access log event yet")
	})
	// Every stored line is one JSON object (NDJSON), including the WAF's own
	// application log events.
	for i, line := range strings.Split(strings.TrimSuffix(readTenantLogs(t, tenantLogsDir), "\n"), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Errorf("stored log line %d is not a JSON object: %v\nline: %s", i+1, err, line)
		}
	}

	// 4. Verify the failed-authentication limiter: the 11th attempt within a
	// minute is throttled, and so is a valid token from the same IP. This step
	// is last because it also locks out the WAF's forwarder.
	for ; authFailures < 10; authFailures++ {
		if status, _ := postLogs("invalid-token", "application/json", logPayload); status != http.StatusForbidden {
			t.Fatalf("Expected 403 for failed authentication %d, got %d", authFailures+1, status)
		}
	}
	if status, _ := postLogs("invalid-token", "application/json", logPayload); status != http.StatusTooManyRequests {
		t.Errorf("Expected 429 after 10 failed authentications, got %d", status)
	}
	if status, _ := postLogs(token, "application/json", logPayload); status != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for a throttled IP with a valid token, got %d", status)
	}
}

// readTenantLogs returns the content of all log files of one tenant. The
// receiver names files by UTC date; reading all of them avoids a failure when
// the date changes during the test.
func readTenantLogs(t *testing.T, tenantLogsDir string) string {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(tenantLogsDir, "*.log"))
	if err != nil {
		t.Fatalf("failed to list log files: %v", err)
	}
	var content strings.Builder
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read log file %s: %v", path, err)
		}
		content.Write(data)
	}
	return content.String()
}

// startAILogsReceiverProcess runs the ai-logs-receiver binary and waits for
// its /readyz. The process is stopped when the test ends.
func startAILogsReceiverProcess(t *testing.T, tenantID, token, logsDir string) string {
	t.Helper()

	binPath := aiLogsReceiverBinary.get(t)
	tokensJSON, err := json.Marshal(map[string]string{tenantID: token})
	if err != nil {
		t.Fatalf("failed to encode AI log tokens: %v", err)
	}

	_, addrs := startListeningProcess(t, "ai-logs-receiver", 1, func(addrs []string) (*exec.Cmd, string) {
		_, port, err := net.SplitHostPort(addrs[0])
		if err != nil {
			t.Fatalf("failed to parse listen address %s: %v", addrs[0], err)
		}
		cmd := exec.Command(binPath)
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(),
			"PORT="+port,
			"AI_LOG_TOKENS="+string(tokensJSON),
			"LOGS_DIR="+logsDir,
		)
		return cmd, "http://" + addrs[0] + "/readyz"
	})
	return "http://" + addrs[0]
}
