package waf

import (
	"encoding/json"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type readinessReporter interface {
	ReadinessReport() ReadinessReport
}

type tenantHostMatcher interface {
	HasTenant(host string) bool
}

// HasTenant reports whether host is served by a configured tenant.
func (h *ProxyHandler) HasTenant(host string) bool {
	return h.registry.HasTenant(host)
}

// NewPublicHTTPHandler serves application traffic and non-sensitive liveness checks.
// /livez and /healthz answer only for hosts that are not tenants, such as the
// pod IP a probe uses. Requests for a tenant host always reach the tenant, so
// an application's own /healthz is never shadowed.
func NewPublicHTTPHandler(proxy http.Handler) http.Handler {
	matcher, _ := proxy.(tenantHostMatcher)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/livez" || r.URL.Path == "/healthz" {
			if matcher == nil || !matcher.HasTenant(r.Host) {
				livezHandler(w, r)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	})
}

// NewAdminHTTPHandler serves operational endpoints on the dedicated admin listener.
func NewAdminHTTPHandler(reporter readinessReporter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", livezHandler)
	mux.HandleFunc("/healthz", livezHandler)
	mux.HandleFunc("/readyz", readyzHandler(reporter))
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

func livezHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func readyzHandler(reporter readinessReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		report := reporter.ReadinessReport()
		statusCode := http.StatusOK
		if !report.Ready {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(report)
	}
}
