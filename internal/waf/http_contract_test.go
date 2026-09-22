package waf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func TestProxyStreamsSSE(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ready\n\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush upstream SSE: %v", err)
		}
	}))
	defer upstream.Close()

	proxy := newContractProxy(t, upstream.URL)
	server := httptest.NewServer(NewPublicHTTPHandler(proxy))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/events", nil)
	if err != nil {
		t.Fatalf("create SSE request: %v", err)
	}
	req.Host = "api.example.com"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("SSE request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read SSE response: %v", err)
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" || string(body) != "data: ready\n\n" {
		t.Fatalf("unexpected SSE response: content-type=%q body=%q", resp.Header.Get("Content-Type"), body)
	}
}

func TestProxySupportsWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack upstream: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err == nil {
			_, _ = io.WriteString(rw, "echo:"+line)
			_ = rw.Flush()
		}
	}))
	defer upstream.Close()

	proxy := newContractProxy(t, upstream.URL)
	server := httptest.NewServer(NewPublicHTTPHandler(proxy))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	conn, err := net.DialTimeout("tcp", serverURL.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprint(conn, "GET /socket HTTP/1.1\r\nHost: api.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", response.StatusCode)
	}
	_, _ = io.WriteString(conn, "ping\n")
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgraded stream: %v", err)
	}
	if line != "echo:ping\n" {
		t.Fatalf("unexpected upgraded response %q", line)
	}
}

func newContractProxy(t *testing.T, upstreamURL string) *ProxyHandler {
	t.Helper()
	registry := NewWAFRegistry()
	proxy := NewProxyHandler(registry)
	tenant := Tenant{Upstreams: []Upstream{{URL: upstreamURL}}}
	state, err := proxy.buildTenantState("api.example.com", tenant)
	if err != nil {
		t.Fatalf("build tenant state: %v", err)
	}
	registry.mapping["api.example.com"] = Entry{Tenant: tenant}
	proxy.tenantStates.Store("api.example.com", state)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func (r *flushRecorder) Flush() {
	r.flushed = true
}

func TestLoggingResponseWriterPreservesFlush(t *testing.T) {
	underlying := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := &loggingResponseWriter{ResponseWriter: underlying, statusCode: http.StatusOK}

	if err := http.NewResponseController(w).Flush(); err != nil {
		t.Fatalf("flush through wrapper: %v", err)
	}
	if !underlying.flushed {
		t.Fatal("expected underlying writer to be flushed")
	}
}

func TestClientIPUsesForwardingOnlyFromTrustedProxy(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	untrustedRequest := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	untrustedRequest.RemoteAddr = "192.0.2.10:1234"
	untrustedRequest.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := clientIPFromRequest(untrustedRequest, true, trusted); got != "192.0.2.10" {
		t.Fatalf("expected untrusted peer address, got %q", got)
	}

	trustedRequest := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	trustedRequest.RemoteAddr = "10.0.0.5:1234"
	trustedRequest.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.4")
	if got := clientIPFromRequest(trustedRequest, true, trusted); got != "203.0.113.9" {
		t.Fatalf("expected forwarded client address, got %q", got)
	}
}

func TestProxyCanonicalizesForwardedClientIP(t *testing.T) {
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	proxy := newContractProxy(t, upstream.URL)
	proxy.trustForwardedFor.Store(true)
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	proxy.trustedProxyCIDRs.Store(&trusted)
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com", nil)
	req.Host = "api.example.com"
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.4")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if got := <-forwarded; got != "203.0.113.9" {
		t.Fatalf("expected validated client address only, got %q", got)
	}
}

func TestUpstreamDialAddressAddsDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://example.com":  "example.com:80",
		"https://example.com": "example.com:443",
	} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URL: %v", err)
		}
		if got := upstreamDialAddress(target); got != want {
			t.Fatalf("%s: expected %q, got %q", raw, want, got)
		}
	}
}

func TestUpstreamTransportHasResponseHeaderTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	proxy := newContractProxy(t, upstream.URL)
	stateValue, ok := proxy.tenantStates.Load("api.example.com")
	if !ok {
		t.Fatal("expected tenant state")
	}
	state := stateValue.(*TenantState)
	transport, ok := state.upstreams[0].Proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected HTTP transport")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("expected bounded upstream response-header wait")
	}
}

func TestAccessLogOmitsQueryString(t *testing.T) {
	var output bytes.Buffer
	SetAccessLogOutput(&output)
	defer SetAccessLogOutput(os.Stdout)

	h := NewProxyHandler(NewWAFRegistry())
	req := httptest.NewRequest(http.MethodGet, "http://unknown.example/path?token=secret", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if strings.Contains(output.String(), "secret") {
		t.Fatalf("access log leaked query string: %s", output.String())
	}
}
