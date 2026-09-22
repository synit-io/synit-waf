package waf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/oschwald/geoip2-golang/v2"
)

type fakeCountryLookup struct {
	country string
	err     error
}

func (f *fakeCountryLookup) LookupCountry(netip.Addr) (string, bool, error) {
	return f.country, f.country != "", f.err
}

func (f *fakeCountryLookup) Close() error { return nil }

type fakeGeoIPCountryReader struct {
	err    error
	closed bool
}

func (f *fakeGeoIPCountryReader) Country(netip.Addr) (*geoip2.Country, error) {
	return &geoip2.Country{}, f.err
}

func (f *fakeGeoIPCountryReader) Close() error {
	f.closed = true
	return nil
}

func TestNewCountryLookupRejectsUnsupportedDatabase(t *testing.T) {
	reader := &fakeGeoIPCountryReader{err: errors.New("country method unsupported")}
	lookup, err := newCountryLookup(reader)
	if err == nil {
		t.Fatal("expected unsupported database to be rejected")
	}
	if lookup != nil {
		t.Fatal("expected no lookup for unsupported database")
	}
	if !reader.closed {
		t.Fatal("expected rejected database reader to be closed")
	}
}

func TestGeoIPBlocksConfiguredCountry(t *testing.T) {
	registry := NewWAFRegistry()
	registry.mapping["api.example.com"] = Entry{Tenant: Tenant{Security: SecurityPolicy{
		GeoIPEnabled:     new(true),
		BlockedCountries: []string{"DE"},
	}}}
	h := NewProxyHandler(registry)
	h.geoIP = &fakeCountryLookup{country: "DE"}

	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	req.Host = "api.example.com"
	req.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected GeoIP block, got %d", w.Code)
	}
}
