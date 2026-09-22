package waf

import (
	"net/url"
	"testing"
)

func TestReadinessReportNotReadyWithoutTenants(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())

	report := h.ReadinessReport()
	if report.Ready {
		t.Fatal("expected readiness to be false when no tenants are configured")
	}
}

func TestReadinessReportReadyWithHealthyTenant(t *testing.T) {
	registry := NewWAFRegistry()
	h := NewProxyHandler(registry)

	registry.mapping["api.example.com"] = Entry{Tenant: Tenant{}}
	u, err := url.Parse("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	up := &UpstreamServer{Tenant: "api.example.com", URL: u}
	up.isHealthy.Store(true)
	h.tenantStates.Store("api.example.com", &TenantState{upstreams: []*UpstreamServer{up}})

	report := h.ReadinessReport()
	if !report.Ready {
		t.Fatalf("expected readiness to be true, got reasons: %v", report.Reasons)
	}
}
