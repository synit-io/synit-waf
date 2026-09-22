package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseMaskingRejectsOversizeResponse(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	h.responseMaskingLimit.Store(4)
	resp := &http.Response{
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader("12345")),
		ContentLength: 5,
	}

	err := h.applyResponseMasking(resp, []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}})
	if err == nil {
		t.Fatal("expected oversized mask-required response to fail closed")
	}
}

func TestResponseMaskingRejectsEncodedResponse(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	resp := &http.Response{
		Header: http.Header{
			"Content-Type":     []string{"text/plain"},
			"Content-Encoding": []string{"gzip"},
		},
		Body:          io.NopCloser(strings.NewReader("encoded-secret")),
		ContentLength: -1,
	}

	if err := h.applyResponseMasking(resp, []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}}); err == nil {
		t.Fatal("expected encoded response to fail closed")
	}
}

func TestResponseMaskingRejectsEventStream(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	resp := &http.Response{
		Header:        http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:          io.NopCloser(strings.NewReader("data: secret\n\n")),
		ContentLength: -1,
	}

	if err := h.applyResponseMasking(resp, []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}}); err == nil {
		t.Fatal("expected masked event stream to fail closed instead of buffering")
	}
}

func TestResponseMaskingRejectsPartialResponse(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	resp := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(strings.NewReader("secret")),
		ContentLength: 6,
	}
	if err := h.applyResponseMasking(resp, []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}}); err == nil {
		t.Fatal("expected partial response to fail closed")
	}
}

func TestResponseMaskingSkipsBodylessResponse(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	resp := &http.Response{
		StatusCode:    http.StatusNoContent,
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
	}

	if err := h.applyResponseMasking(resp, []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}}); err != nil {
		t.Fatalf("expected bodyless response to bypass masking: %v", err)
	}
}

func TestResponseMaskingOversizeReturnsBadGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "secret-value")
	}))
	defer upstream.Close()

	registry := NewWAFRegistry()
	h := NewProxyHandler(registry)
	h.responseMaskingLimit.Store(4)
	tenant := Tenant{
		Upstreams: []Upstream{{URL: upstream.URL}},
		Security: SecurityPolicy{ResponseMasking: []ResponseMaskingRule{{
			Pattern:     "secret",
			Replacement: "masked",
		}}},
	}
	state, err := h.buildTenantState("api.example.com", tenant)
	if err != nil {
		t.Fatalf("build tenant state: %v", err)
	}
	registry.mapping["api.example.com"] = Entry{Tenant: tenant}
	h.tenantStates.Store("api.example.com", state)

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/data", nil)
	req.Host = "api.example.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestResponseMaskingStripsRangeBeforeProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" || r.Header.Get("If-Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, "secret")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "prefix=secret")
	}))
	defer upstream.Close()
	registry := NewWAFRegistry()
	h := NewProxyHandler(registry)
	tenant := Tenant{Upstreams: []Upstream{{URL: upstream.URL}}}
	tenant.Security.ResponseMasking = []ResponseMaskingRule{{Pattern: `prefix=secret`, Replacement: "masked"}}
	state, err := h.buildTenantState("api.example.com", tenant)
	if err != nil {
		t.Fatalf("build state: %v", err)
	}
	registry.mapping["api.example.com"] = Entry{Tenant: tenant}
	h.tenantStates.Store("api.example.com", state)
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/data", nil)
	req.Host = "api.example.com"
	req.Header.Set("Range", "bytes=7-12")
	req.Header.Set("If-Range", `"etag"`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "masked" {
		t.Fatalf("expected full masked response, got %d %q", w.Code, w.Body.String())
	}
}
