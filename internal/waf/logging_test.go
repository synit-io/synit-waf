package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestWebhookLogHookUsesBoundedQueue(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	hook := newWebhookLogHook(server.URL, "", 1, 1, time.Second)
	t.Cleanup(func() {
		if err := hook.Close(); err != nil {
			t.Errorf("close webhook hook: %v", err)
		}
	})
	entry := &logrus.Entry{Logger: logrus.New(), Level: logrus.InfoLevel, Message: "test", Time: time.Now()}
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("first fire: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start request")
	}
	_ = hook.Fire(entry)
	_ = hook.Fire(entry)
	if hook.dropped.Load() == 0 {
		t.Fatal("expected full queue to drop an event")
	}
	close(release)
}

func TestWebhookLogHookDropsOversizePayload(t *testing.T) {
	hook := newWebhookLogHook("http://127.0.0.1", "", 1, 1, time.Second)
	t.Cleanup(func() { _ = hook.Close() })
	entry := &logrus.Entry{Logger: logrus.New(), Level: logrus.InfoLevel, Message: strings.Repeat("x", maxForwardedLogPayloadBytes+1), Time: time.Now()}
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("fire oversize entry: %v", err)
	}
	if hook.dropped.Load() != 1 {
		t.Fatal("expected oversize payload to be dropped")
	}
}

func TestWebhookLogHookCloseIsBounded(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.Close()
	}()
	hook := newWebhookLogHook(server.URL, "", 1, 1, time.Minute)
	hook.shutdownTimeout = 20 * time.Millisecond
	entry := &logrus.Entry{Logger: logrus.New(), Level: logrus.InfoLevel, Message: "test", Time: time.Now()}
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("fire: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not start")
	}
	start := time.Now()
	if err := hook.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("close exceeded bound: %v", elapsed)
	}
}

func TestWebhookLogHookCountsDeliveryFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	hook := newWebhookLogHook(server.URL, "", 1, 1, time.Second)
	entry := &logrus.Entry{Logger: logrus.New(), Level: logrus.InfoLevel, Message: "test", Time: time.Now()}
	if err := hook.Fire(entry); err != nil {
		t.Fatalf("fire: %v", err)
	}
	if err := hook.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if hook.dropped.Load() != 1 {
		t.Fatalf("expected delivery failure to be counted, got %d", hook.dropped.Load())
	}
}

func TestSetupLoggingFailsWhenEnabledSinkCannotOpen(t *testing.T) {
	cfg := AppConfig{}
	cfg.Logging.AccessLog.Enabled = true
	cfg.Logging.AccessLog.Path = t.TempDir()
	cfg.Logging.AccessLog.Format = "json"
	if err := SetupLogging(cfg); err == nil {
		t.Fatal("expected directory path to fail as a log file")
	}
}
