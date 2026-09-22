package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken      = "test-token-0123456789abcdef0123456789"
	otherTestToken = "other-token-0123456789abcdef012345678"
)

var testNow = time.Date(2026, time.March, 4, 23, 59, 59, 0, time.UTC)

func newTestReceiver(logsDir string, maxRequestBytes, maxTenantBytes int64, requestsPerMinute int) *LogReceiver {
	receiver := newLogReceiver(map[string]string{"tenant-a": testToken}, logsDir, maxRequestBytes, maxTenantBytes, requestsPerMinute, 24*time.Hour)
	receiver.now = func() time.Time { return testNow }
	return receiver
}

func newLogRequest(token, contentType string, body io.Reader) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/logs", body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func postLog(receiver *LogReceiver, token, contentType, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	receiver.handleLogs(rr, newLogRequest(token, contentType, strings.NewReader(body)))
	return rr
}

func testLogFile(logsDir string) string {
	return filepath.Join(logsDir, "tenant-a", testNow.Format("2006-01-02")+".log")
}

func TestLoadTenantTokens(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "valid", raw: `{"tenant-a":"` + testToken + `"}`},
		{name: "minimum length token", raw: `{"tenant-a":"` + strings.Repeat("a", minTokenLength) + `"}`},
		{name: "empty", raw: ``, wantErr: true},
		{name: "invalid JSON", raw: `{`, wantErr: true},
		{name: "no tenants", raw: `{}`, wantErr: true},
		{name: "unsafe tenant ID", raw: `{"../tenant":"` + testToken + `"}`, wantErr: true},
		{name: "portable unsafe tenant ID", raw: `{"..\\tenant":"` + testToken + `"}`, wantErr: true},
		{name: "parent tenant ID", raw: `{"..":"` + testToken + `"}`, wantErr: true},
		{name: "tenant ID with control", raw: "{\"tenant\\nname\":\"" + testToken + "\"}", wantErr: true},
		{name: "tenant ID too long", raw: `{"` + strings.Repeat("a", 129) + `":"` + testToken + `"}`, wantErr: true},
		{name: "empty token", raw: `{"tenant-a":""}`, wantErr: true},
		{name: "short token", raw: `{"tenant-a":"` + strings.Repeat("a", minTokenLength-1) + `"}`, wantErr: true},
		{name: "padded short token", raw: `{"tenant-a":"secret` + strings.Repeat(" ", minTokenLength) + `"}`, wantErr: true},
		{name: "duplicate token", raw: `{"tenant-a":"` + testToken + `","tenant-b":"` + testToken + `"}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadTenantTokens(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadTenantTokens() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHealthCheck(t *testing.T) {
	receiver := &LogReceiver{}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rr := httptest.NewRecorder()
		receiver.handleHealthz(rr, httptest.NewRequest(method, "/healthz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", method, rr.Code)
		}
		if rr.Body.String() != "ok" {
			t.Fatalf("%s: expected 'ok', got %q", method, rr.Body.String())
		}
	}
}

func TestProbesRejectOtherMethods(t *testing.T) {
	receiver := newTestReceiver(t.TempDir(), 1024, 1024, 10)
	handlers := map[string]http.HandlerFunc{"/healthz": receiver.handleHealthz, "/readyz": receiver.handleReadyz}
	for path, handler := range handlers {
		rr := httptest.NewRecorder()
		handler(rr, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: expected 405, got %d", path, rr.Code)
		}
		if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
			t.Fatalf("%s: expected Allow 'GET, HEAD', got %q", path, got)
		}
	}
}

func TestReadyzReportsUnwritableLogsDir(t *testing.T) {
	// A regular file in place of the logs directory fails for every user, including root.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	now := testNow
	receiver := newTestReceiver(blocked, 1024, 1024, 10)
	receiver.now = func() time.Time { return now }

	rr := httptest.NewRecorder()
	receiver.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}

	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	receiver.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected cached 503, got %d", rr.Code)
	}

	now = now.Add(readinessCacheInterval)
	rr = httptest.NewRecorder()
	receiver.handleReadyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after the directory became writable, got %d", rr.Code)
	}
	entries, err := os.ReadDir(blocked)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected probe file removed, found %d entries", len(entries))
	}
}

func TestLogIngestionWithValidToken(t *testing.T) {
	logsDir := t.TempDir()
	t.Setenv("LOGS_DIR", logsDir)
	receiver := &LogReceiver{tokens: map[string]string{"tenant-a": testToken}, now: func() time.Time { return testNow }}

	rr := postLog(receiver, testToken, "application/json; charset=utf-8", `{"message":"test log entry"}`)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	content, err := os.ReadFile(testLogFile(logsDir))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if string(content) != `{"message":"test log entry"}`+"\n" {
		t.Fatalf("unexpected log content %q", content)
	}
}

func TestLogIngestionStoresNDJSONBatch(t *testing.T) {
	logsDir := t.TempDir()
	receiver := newTestReceiver(logsDir, 1024, 1024, 10)

	rr := postLog(receiver, testToken, "application/x-ndjson", "{\"n\":1}\n\n{\"n\":2}\n{\"n\":3}")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	content, err := os.ReadFile(testLogFile(logsDir))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if want := "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n"; string(content) != want {
		t.Fatalf("expected %q, got %q", want, content)
	}
}

func TestLogIngestionValidatesBody(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        int
	}{
		{name: "missing content type", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "text content type", contentType: "text/plain", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "malformed content type", contentType: "application/json;;", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "empty body", contentType: "application/json", body: "", want: http.StatusBadRequest},
		{name: "only newlines", contentType: "application/x-ndjson", body: "\n\n", want: http.StatusBadRequest},
		{name: "not JSON", contentType: "application/json", body: "test log entry", want: http.StatusBadRequest},
		{name: "forged second line", contentType: "application/x-ndjson", body: "{\"n\":1}\nforged entry", want: http.StatusBadRequest},
		{name: "JSON object spanning lines", contentType: "application/x-ndjson", body: "{\"n\":\n1}", want: http.StatusBadRequest},
		{name: "batch sent as application/json", contentType: "application/json", body: "{\"n\":1}\n{\"n\":2}", want: http.StatusBadRequest},
		{name: "carriage return", contentType: "application/x-ndjson", body: "{\"n\":1}\r\n", want: http.StatusBadRequest},
		{name: "raw tab between tokens", contentType: "application/json", body: "{\"n\":\t1}", want: http.StatusBadRequest},
		{name: "raw escape in string", contentType: "application/json", body: "{\"n\":\"\x1b[2K\"}", want: http.StatusBadRequest},
		{name: "escaped control characters", contentType: "application/json", body: `{"n":"a\nb\u001b"}`, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logsDir := t.TempDir()
			receiver := newTestReceiver(logsDir, 1024, 1024, 10)
			rr := postLog(receiver, testToken, tt.contentType, tt.body)
			if rr.Code != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, rr.Code)
			}
			if _, err := os.Stat(testLogFile(logsDir)); tt.want != http.StatusOK && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected body must not be stored, stat error = %v", err)
			}
		})
	}
}

func TestLogIngestionRejectsOtherMethods(t *testing.T) {
	receiver := newTestReceiver(t.TempDir(), 1024, 1024, 10)
	rr := httptest.NewRecorder()
	receiver.handleLogs(rr, httptest.NewRequest(http.MethodGet, "/logs", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("expected Allow POST, got %q", got)
	}
}

func TestLogIngestionRejectsMissingToken(t *testing.T) {
	receiver := &LogReceiver{tokens: map[string]string{"tenant-a": testToken}}

	rr := postLog(receiver, "", "application/json", `{"message":"no token"}`)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestLogIngestionRejectsInvalidToken(t *testing.T) {
	receiver := &LogReceiver{tokens: map[string]string{"tenant-a": testToken}}

	rr := postLog(receiver, otherTestToken, "application/json", `{"message":"bad token"}`)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestLogIngestionThrottlesFailedAuthentication(t *testing.T) {
	now := testNow
	receiver := newTestReceiver(t.TempDir(), 1024, 1024, 100)
	receiver.now = func() time.Time { return now }

	for i := range maxAuthFailures {
		token := otherTestToken
		if i%2 == 0 {
			token = ""
		}
		if rr := postLog(receiver, token, "application/json", `{}`); rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden {
			t.Fatalf("failure %d expected 401 or 403, got %d", i, rr.Code)
		}
	}
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled client expected 429 even with a valid token, got %d", rr.Code)
	}

	otherClient := newLogRequest(testToken, "application/json", strings.NewReader(`{}`))
	otherClient.RemoteAddr = "198.51.100.7:4321"
	rr := httptest.NewRecorder()
	receiver.handleLogs(rr, otherClient)
	if rr.Code != http.StatusOK {
		t.Fatalf("other client expected 200, got %d", rr.Code)
	}

	now = now.Add(authFailureWindow)
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after the failure window, got %d", rr.Code)
	}
}

func TestAuthFailureLimiterStaysBounded(t *testing.T) {
	var limiter authFailureLimiter
	for i := range maxAuthFailureClients {
		limiter.recordFailure(fmt.Sprintf("client-%d", i), testNow)
	}
	limiter.recordFailure("one-more", testNow)
	if got := len(limiter.clients); got != maxAuthFailureClients {
		t.Fatalf("expected %d tracked clients without expiry, got %d", maxAuthFailureClients, got)
	}

	limiter.recordFailure("after-expiry", testNow.Add(authFailureWindow))
	if got := len(limiter.clients); got != 1 {
		t.Fatalf("expected expired clients evicted, got %d", got)
	}
}

func TestRemoteIP(t *testing.T) {
	tests := map[string]string{
		"192.0.2.1:1234":     "192.0.2.1",
		"[2001:db8::1]:1234": "2001:db8::1",
		"no-port":            "no-port",
	}
	for remoteAddr, want := range tests {
		if got := remoteIP(&http.Request{RemoteAddr: remoteAddr}); got != want {
			t.Fatalf("remoteIP(%q) = %q, want %q", remoteAddr, got, want)
		}
	}
}

func TestCleanupExpiredLogsIncludesInactiveTenant(t *testing.T) {
	logsDir := t.TempDir()
	inactiveDir := filepath.Join(logsDir, "inactive")
	if err := os.MkdirAll(inactiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(inactiveDir, "old.log")
	if err := os.WriteFile(oldPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := testNow.Add(-48 * time.Hour)
	if err := os.Chtimes(oldPath, old, old); err != nil {
		t.Fatal(err)
	}
	receiver := newTestReceiver(logsDir, 1024, 1024, 10)
	if err := receiver.cleanupExpiredLogs(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected inactive tenant log removed, got %v", err)
	}
}

func TestCleanupExpiredLogsIgnoresMissingLogsDir(t *testing.T) {
	receiver := newTestReceiver(filepath.Join(t.TempDir(), "missing"), 1024, 1024, 10)
	if err := receiver.cleanupExpiredLogs(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func TestLogIngestionRejectsOversizeRequest(t *testing.T) {
	receiver := newTestReceiver(t.TempDir(), 4, 1024, 100)

	rr := postLog(receiver, testToken, "application/json", `{"n":1}`)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}

	// Without a Content-Length the limit is enforced while reading.
	rr = httptest.NewRecorder()
	receiver.handleLogs(rr, newLogRequest(testToken, "application/json", io.MultiReader(strings.NewReader(`{"n":1}`))))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for a chunked body, got %d", rr.Code)
	}
}

func TestLogIngestionEnforcesTenantStorageQuota(t *testing.T) {
	receiver := newTestReceiver(t.TempDir(), 1024, 5, 100)
	for i, want := range []int{http.StatusOK, http.StatusInsufficientStorage} {
		if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != want {
			t.Fatalf("request %d expected %d, got %d", i, want, rr.Code)
		}
	}
}

func TestTenantStorageQuotaCountsExistingFiles(t *testing.T) {
	logsDir := t.TempDir()
	tenantDir := filepath.Join(logsDir, "tenant-a")
	if err := os.MkdirAll(tenantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "2026-03-03.log"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiver := newTestReceiver(logsDir, 1024, 5, 100)

	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507 from usage found on disk, got %d", rr.Code)
	}
}

func TestRetentionSweepReconcilesTenantUsage(t *testing.T) {
	logsDir := t.TempDir()
	now := testNow
	receiver := newTestReceiver(logsDir, 1024, 5, 100)
	receiver.now = func() time.Time { return now }

	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d", rr.Code)
	}

	// Expiry runs only in the sweep; afterwards the freed bytes are available again.
	expired := now.Add(-48 * time.Hour)
	if err := os.Chtimes(testLogFile(logsDir), expired, expired); err != nil {
		t.Fatal(err)
	}
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507 before the sweep, got %d", rr.Code)
	}
	if err := receiver.cleanupExpiredLogs(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if got := receiver.tenantState("tenant-a").usedBytes; got != 0 {
		t.Fatalf("expected reconciled usage 0, got %d", got)
	}
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after the sweep, got %d", rr.Code)
	}
}

func TestLogIngestionRateLimitsTenant(t *testing.T) {
	now := testNow
	receiver := newTestReceiver(t.TempDir(), 1024, 1024, 1)
	receiver.now = func() time.Time { return now }

	// Rate limiting is per request, not per line.
	if rr := postLog(receiver, testToken, "application/x-ndjson", "{}\n{}\n{}\n"); rr.Code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", rr.Code)
	}
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", rr.Code)
	}

	now = now.Add(time.Minute)
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusOK {
		t.Fatalf("request in the next window expected 200, got %d", rr.Code)
	}
}

func TestSlowUploadDoesNotBlockTenant(t *testing.T) {
	logsDir := t.TempDir()
	receiver := newTestReceiver(logsDir, 1024, 1024, 2)

	body, slowWriter := io.Pipe()
	slowDone := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		receiver.handleLogs(rr, newLogRequest(testToken, "application/json", body))
		slowDone <- rr.Code
	}()
	// The pipe write returns once the handler is reading the slow body.
	if _, err := slowWriter.Write([]byte(`{"slow":`)); err != nil {
		t.Fatal(err)
	}

	fastDone := make(chan int, 1)
	go func() { fastDone <- postLog(receiver, testToken, "application/json", `{"fast":true}`).Code }()
	select {
	case code := <-fastDone:
		if code != http.StatusOK {
			t.Fatalf("fast request expected 200, got %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fast request blocked behind a slow upload of the same tenant")
	}

	// The unfinished upload already counts against the request rate.
	if rr := postLog(receiver, testToken, "application/json", `{}`); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("third request expected 429, got %d", rr.Code)
	}

	if _, err := slowWriter.Write([]byte(`true}`)); err != nil {
		t.Fatal(err)
	}
	if err := slowWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if code := <-slowDone; code != http.StatusOK {
		t.Fatalf("slow request expected 200, got %d", code)
	}
	content, err := os.ReadFile(testLogFile(logsDir))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if want := "{\"fast\":true}\n{\"slow\":true}\n"; string(content) != want {
		t.Fatalf("expected %q, got %q", want, content)
	}
}

func TestConcurrentLogIngestionPreservesLines(t *testing.T) {
	logsDir := t.TempDir()
	receiver := newTestReceiver(logsDir, 1024, 1<<20, 1000)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := postLog(receiver, testToken, "application/json", fmt.Sprintf(`{"entry":%d}`, i))
			if rr.Code != http.StatusOK {
				t.Errorf("request %d expected 200, got %d", i, rr.Code)
			}
		}()
	}
	wg.Wait()

	content, err := os.ReadFile(testLogFile(logsDir))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(content)), "\n")); got != 50 {
		t.Fatalf("expected 50 complete lines, got %d", got)
	}
	if got := receiver.tenantState("tenant-a").usedBytes; got != int64(len(content)) {
		t.Fatalf("expected cached usage %d, got %d", len(content), got)
	}
}

func TestRunRetentionSweepsUntilCancelled(t *testing.T) {
	logsDir := t.TempDir()
	tenantDir := filepath.Join(logsDir, "tenant-a")
	if err := os.MkdirAll(tenantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	receiver := newTestReceiver(logsDir, 1024, 1024, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		receiver.runRetention(ctx, 5*time.Millisecond)
		close(done)
	}()

	// One file for the startup sweep, one created later for a ticker sweep.
	expired := testNow.Add(-48 * time.Hour)
	for _, name := range []string{"startup.log", "ticker.log"} {
		path := filepath.Join(tenantDir, name)
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, expired, expired); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s was not removed by the retention sweep", name)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runRetention did not stop after cancellation")
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunRetentionLogsSweepErrors(t *testing.T) {
	// A regular file in place of the logs directory makes every sweep fail.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var output lockedBuffer
	log.SetOutput(&output)
	defer log.SetOutput(os.Stderr)

	receiver := newTestReceiver(blocked, 1024, 1024, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		receiver.runRetention(ctx, 5*time.Millisecond)
		close(done)
	}()

	// Expect the startup sweep and at least one ticker sweep to be reported.
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(output.String(), "Failed to enforce periodic log retention") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("expected two reported sweep failures, got %q", output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestPositiveInt64Env(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int64
		wantErr bool
	}{
		{name: "unset uses fallback", raw: "", want: 7},
		{name: "blank uses fallback", raw: "  ", want: 7},
		{name: "valid", raw: " 42 ", want: 42},
		{name: "zero", raw: "0", wantErr: true},
		{name: "negative", raw: "-1", wantErr: true},
		{name: "not a number", raw: "ten", wantErr: true},
		{name: "overflow", raw: "9223372036854775808", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TEST_POSITIVE_INT", tt.raw)
			got, err := positiveInt64Env("TEST_POSITIVE_INT", 7)
			if (err != nil) != tt.wantErr {
				t.Fatalf("positiveInt64Env() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("positiveInt64Env() = %d, want %d", got, tt.want)
			}
			if err != nil && !strings.Contains(err.Error(), "TEST_POSITIVE_INT") {
				t.Fatalf("error %q does not name the variable", err)
			}
		})
	}
}

func TestPositiveDurationEnv(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{name: "unset uses fallback", raw: "", want: time.Hour},
		{name: "valid", raw: " 90m ", want: 90 * time.Minute},
		{name: "zero", raw: "0s", wantErr: true},
		{name: "negative", raw: "-1h", wantErr: true},
		{name: "missing unit", raw: "30", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TEST_POSITIVE_DURATION", tt.raw)
			got, err := positiveDurationEnv("TEST_POSITIVE_DURATION", time.Hour)
			if (err != nil) != tt.wantErr {
				t.Fatalf("positiveDurationEnv() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("positiveDurationEnv() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRunReturnsConfigurationErrors(t *testing.T) {
	validTokens := `{"tenant-a":"` + testToken + `"}`
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "missing tokens", env: map[string]string{"AI_LOG_TOKENS": ""}, want: "AI_LOG_TOKENS"},
		{name: "short token", env: map[string]string{"AI_LOG_TOKENS": `{"tenant-a":"secret"}`}, want: "at least 32 characters"},
		{name: "request bytes", env: map[string]string{"AI_LOG_TOKENS": validTokens, "MAX_REQUEST_BYTES": "0"}, want: "MAX_REQUEST_BYTES"},
		{name: "tenant bytes", env: map[string]string{"AI_LOG_TOKENS": validTokens, "MAX_TENANT_BYTES": "x"}, want: "MAX_TENANT_BYTES"},
		{name: "requests per minute", env: map[string]string{"AI_LOG_TOKENS": validTokens, "REQUESTS_PER_MINUTE": "-5"}, want: "REQUESTS_PER_MINUTE"},
		{name: "retention", env: map[string]string{"AI_LOG_TOKENS": validTokens, "RETENTION": "soon"}, want: "RETENTION"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"MAX_REQUEST_BYTES", "MAX_TENANT_BYTES", "REQUESTS_PER_MINUTE", "RETENTION"} {
				t.Setenv(name, "")
			}
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			err := run()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
