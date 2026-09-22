package waf

import "testing"

func TestNormalizeHost(t *testing.T) {
	if got := normalizeHost("Example.COM:8443"); got != "example.com" {
		t.Fatalf("unexpected host normalization: %q", got)
	}
}

func TestRegistryGet_ExactAndWildcard(t *testing.T) {
	r := &SafeWAFRegistry{
		mapping: map[string]Entry{
			"api.example.com":       {Tenant: Tenant{Upstreams: []Upstream{{URL: "http://exact"}}}},
			"*.example.com":         {Tenant: Tenant{Upstreams: []Upstream{{URL: "http://wild"}}}},
			"*.service.example.com": {Tenant: Tenant{Upstreams: []Upstream{{URL: "http://specific"}}}},
		},
	}

	entry, domain, ok := r.Get("API.EXAMPLE.COM:443")
	if !ok {
		t.Fatal("expected exact domain match")
	}
	if domain != "api.example.com" {
		t.Fatalf("expected exact domain, got %q", domain)
	}
	if len(entry.Tenant.Upstreams) != 1 || entry.Tenant.Upstreams[0].URL != "http://exact" {
		t.Fatalf("unexpected entry for exact domain: %+v", entry.Tenant.Upstreams)
	}

	entry, domain, ok = r.Get("foo.service.example.com")
	if !ok {
		t.Fatal("expected wildcard match")
	}
	if domain != "*.service.example.com" {
		t.Fatalf("expected most specific wildcard, got %q", domain)
	}
	if len(entry.Tenant.Upstreams) != 1 || entry.Tenant.Upstreams[0].URL != "http://specific" {
		t.Fatalf("unexpected entry for wildcard domain: %+v", entry.Tenant.Upstreams)
	}
}
