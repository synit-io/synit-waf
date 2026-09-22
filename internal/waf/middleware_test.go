package waf

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

func TestCheckBasicAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	h := NewProxyHandler(NewWAFRegistry())
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.SetBasicAuth("alice", "secret")

	ok, updatedReq := h.checkBasicAuth(req, []BasicAuthCredentials{{User: "alice", Password: string(hash)}})
	if !ok {
		t.Fatal("expected auth success")
	}
	if updatedReq.Context().Value(authenticatedUserKey) != "alice" {
		t.Fatal("expected authenticated username in context")
	}
}

func TestApplyWAFRejectsOversizeBody(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	h.requestBodyLimit.Store(4)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	if err != nil {
		t.Fatalf("failed to create test WAF: %v", err)
	}

	req := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader("12345"))
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	interrupted := h.applyWAF(rr, req, waf)
	if !interrupted {
		t.Fatal("expected oversize body to interrupt request")
	}
	if rr.Code != 413 {
		t.Fatalf("expected 413 for oversize body, got %d", rr.Code)
	}
}

func TestApplyWAFRejectsCompressedBody(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	if err != nil {
		t.Fatalf("create test WAF: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader("compressed"))
	req.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()

	if interrupted := h.applyWAF(w, req, waf); !interrupted {
		t.Fatal("expected compressed inspected body to be rejected")
	}
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", w.Code)
	}
}

func TestApplyWAFRejectsBodyProcessorFailure(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "@streq application/json" "id:1001,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
` + requestBodyErrorRule))
	if err != nil {
		t.Fatalf("create test WAF: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(`{"broken":`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	if interrupted := h.applyWAF(w, req, waf); !interrupted {
		t.Fatal("expected invalid inspected body to be rejected")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestApplyWAFUsesValidatedClientIPAndHost(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	h.trustForwardedFor.Store(true)
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h.trustedProxyCIDRs.Store(&trusted)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRule REMOTE_ADDR "!@ipMatch 203.0.113.9" "id:1001,phase:1,deny,status:403"
SecRule REQUEST_HEADERS:Host "!@streq api.example.com" "id:1002,phase:1,deny,status:403"
`))
	if err != nil {
		t.Fatalf("create test WAF: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/path", nil)
	req.Host = "api.example.com"
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()

	if interrupted := h.applyWAF(w, req, waf); interrupted {
		t.Fatalf("expected validated client identity and Host to satisfy WAF rules, got %d", w.Code)
	}
}

func TestRateLimitBlocksExcessRequests(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	policy := RateLimitPolicy{
		RequestsPerMinute: 1,
		Burst:             1,
	}

	if !h.allowRateLimitedRequest("api.example.com", "127.0.0.1", policy) {
		t.Fatal("expected first request to pass rate limiter")
	}
	if h.allowRateLimitedRequest("api.example.com", "127.0.0.1", policy) {
		t.Fatal("expected second immediate request to be rate limited")
	}
}

func TestRateLimitConcurrentFirstRequestsShareLimiter(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	policy := RateLimitPolicy{RequestsPerMinute: 1, Burst: 1}
	start := make(chan struct{})
	var allowed atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			<-start
			if h.allowRateLimitedRequest("api.example.com", "127.0.0.1", policy) {
				allowed.Add(1)
			}
		})
	}
	close(start)
	workers.Wait()
	if got := allowed.Load(); got != 1 {
		t.Fatalf("expected exactly one initial burst request, got %d", got)
	}
}

func TestGlobalRateLimitBlocksExcessRequests(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	h.globalLimiter.Store(rate.NewLimiter(rate.Limit(1.0/60.0), 1)) // 1 request per minute, burst 1

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()

	// First request should pass global limiter (but might fail tenant check, which is OK)
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusTooManyRequests {
		t.Fatal("expected first request to pass global rate limiter")
	}

	// Second request should be blocked by global limiter
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be blocked by global rate limiter, got %d", rr2.Code)
	}
}
