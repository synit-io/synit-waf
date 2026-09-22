package waf

import "time"

// ReadinessReport describes current runtime readiness state.
type ReadinessReport struct {
	Ready                      bool      `json:"ready"`
	CheckedAt                  time.Time `json:"checked_at"`
	ConfiguredTenants          int       `json:"configured_tenants"`
	TenantsWithHealthyUpstream int       `json:"tenants_with_healthy_upstream"`
	Reasons                    []string  `json:"reasons,omitempty"`
}

// ReadinessReport aggregates the health status of all WAF dependencies and configured tenants.
func (h *ProxyHandler) ReadinessReport() ReadinessReport {
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()

	report := ReadinessReport{CheckedAt: time.Now().UTC()}

	if h.crowdsecRequired.Load() && (h.bouncer.Load() == nil || !h.crowdsecHealthy.Load()) {
		report.Reasons = append(report.Reasons, "crowdsec is required by fail-closed policy but is unavailable")
	}

	h.registry.RLock()
	configured := len(h.registry.mapping)
	tenantNames := make([]string, 0, configured)
	for tenantName := range h.registry.mapping {
		tenantNames = append(tenantNames, tenantName)
	}
	h.registry.RUnlock()

	report.ConfiguredTenants = configured
	if configured == 0 {
		report.Reasons = append(report.Reasons, "no tenants are configured")
	}

	for _, tenantName := range tenantNames {
		stateValue, ok := h.tenantStates.Load(tenantName)
		if !ok {
			report.Reasons = append(report.Reasons, "tenant "+tenantName+" has no upstream state")
			continue
		}

		state := stateValue.(*TenantState)
		if len(state.upstreams) == 0 {
			report.Reasons = append(report.Reasons, "tenant "+tenantName+" has no configured upstreams")
			continue
		}

		healthy := false
		for _, upstream := range state.upstreams {
			if upstream.isHealthy.Load() {
				healthy = true
				break
			}
		}
		if healthy {
			report.TenantsWithHealthyUpstream++
			continue
		}

		report.Reasons = append(report.Reasons, "tenant "+tenantName+" has no healthy upstream")
	}

	report.Ready = len(report.Reasons) == 0
	return report
}
