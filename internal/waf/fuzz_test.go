package waf

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func FuzzParseJWK(f *testing.F) {
	f.Add(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`)
	f.Add(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`)
	f.Add(`{"kty":"OKP","crv":"Ed25519","x":"AA"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		var jwk map[string]any
		if json.Unmarshal([]byte(raw), &jwk) != nil {
			return
		}
		key, err := parseJWK(jwk)
		if err == nil && key == nil {
			t.Fatal("parseJWK returned neither a key nor an error")
		}
	})
}

func FuzzClientIPFromRequest(f *testing.F) {
	f.Add("10.0.0.5:1234", "203.0.113.9, 10.0.0.7")
	f.Add("[2001:db8::1]:443", "not-an-ip")
	f.Add("garbage", ",,,")
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	f.Fuzz(func(t *testing.T, remoteAddr, forwardedFor string) {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = remoteAddr
		if strings.ContainsAny(forwardedFor, "\r\n") {
			return
		}
		req.Header.Set("X-Forwarded-For", forwardedFor)
		got := clientIPFromRequest(req, true, trusted)
		// A parsable peer must always yield a parsable client address.
		if peer, err := netip.ParseAddrPort(remoteAddr); err == nil {
			if _, err := netip.ParseAddr(got); err != nil {
				t.Fatalf("peer %v produced unparsable client IP %q", peer, got)
			}
		}
	})
}

func FuzzCheckGraphQLRequest(f *testing.F) {
	f.Add(`{ user(id: "1") { name friends { name } } }`)
	f.Add(`query Q { ...F } fragment F on T { a ...F }`)
	f.Add(`{ a(text: """ {{{ """) }`)
	policy := GraphQLProtection{Enabled: true, BlockIntrospection: true, MaxQueryDepth: 8, MaxQueryBytes: 4096}
	f.Fuzz(func(_ *testing.T, query string) {
		_ = checkGraphQLRequest(query, policy)
	})
}

func FuzzNormalizeHost(f *testing.F) {
	f.Add("API.Example.com.:8443")
	f.Add("[::1]")
	f.Fuzz(func(t *testing.T, host string) {
		normalized := normalizeHost(host)
		if normalizeHost(normalized) != normalized && !strings.ContainsAny(normalized, ":[]. \t") {
			t.Fatalf("normalizeHost is not idempotent for %q: %q", host, normalized)
		}
	})
}
