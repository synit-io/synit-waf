package waf

import (
	"testing"
	"time"
)

func TestRestartHealthChecksCancelsOldContext(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	oldCtx := h.restartHealthChecks()
	_ = h.restartHealthChecks()

	select {
	case <-oldCtx.Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected previous health check context to be canceled")
	}
}
