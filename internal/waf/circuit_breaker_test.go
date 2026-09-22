package waf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreakerAccumulatesFailureStatuses(t *testing.T) {
	var requests atomic.Int32
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstreamServer.Close()

	h := NewProxyHandler(NewWAFRegistry())
	tenant := Tenant{Upstreams: []Upstream{{URL: upstreamServer.URL}}}
	tenant.Security.CircuitBreaker.Enabled = true
	tenant.Security.CircuitBreaker.Threshold = 2
	tenant.Security.CircuitBreaker.Cooldown = time.Minute
	tenant.Security.CircuitBreaker.FailureStatusCodes = []int{http.StatusServiceUnavailable}
	state, err := h.buildTenantState("api.example.com", tenant)
	if err != nil {
		t.Fatalf("build tenant state: %v", err)
	}
	upstream := state.upstreams[0]

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
		w := httptest.NewRecorder()
		upstream.Proxy.ServeHTTP(w, req)
	}

	if got := upstream.consecutiveFailures.Load(); got != 2 {
		t.Fatalf("expected two consecutive failures, got %d", got)
	}
	if upstream.deadUntil.Load() == 0 {
		t.Fatal("expected circuit to open after threshold")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected two upstream requests, got %d", got)
	}
}

func TestCircuitBreakerIgnoresClientCancellation(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	tenant := Tenant{Upstreams: []Upstream{{URL: "http://127.0.0.1:1"}}}
	tenant.Security.CircuitBreaker.Enabled = true
	tenant.Security.CircuitBreaker.Threshold = 1
	state, err := h.buildTenantState("api.example.com", tenant)
	if err != nil {
		t.Fatalf("build tenant state: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com", nil).WithContext(ctx)
	state.upstreams[0].Proxy.ErrorHandler(httptest.NewRecorder(), req, errors.New("upstream: context canceled"))
	if state.upstreams[0].consecutiveFailures.Load() != 0 {
		t.Fatal("client cancellation must not count as an upstream failure")
	}
}
