package waf

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "synit_waf_http_requests_total",
			Help: "Total number of HTTP requests processed by Synit WAF.",
		},
		[]string{"tenant", "status_class"},
	)

	blockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "synit_waf_blocked_requests_total",
			Help: "Total number of blocked requests by decision source.",
		},
		[]string{"source", "tenant"},
	)

	upstreamHealthy = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "synit_waf_upstream_healthy",
			Help: "Whether an upstream is currently healthy (1 healthy, 0 unhealthy).",
		},
		[]string{"tenant", "upstream"},
	)

	configReloadTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "synit_waf_config_reload_total",
			Help: "Total number of configuration reload attempts.",
		},
		[]string{"result"},
	)

	auditModeEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "synit_waf_audit_mode_events_total",
			Help: "Total number of requests that would have been blocked but were allowed due to audit mode.",
		},
		[]string{"tenant"},
	)

	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "synit_waf_http_request_duration_seconds",
			Help:    "Time from request arrival to the end of the response, including upstream time.",
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
		[]string{"tenant"},
	)

	upstreamRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "synit_waf_upstream_requests_total",
			Help: "Total number of proxied requests by upstream and result (status class or error).",
		},
		[]string{"tenant", "upstream", "result"},
	)

	ruleMatchesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "synit_waf_rule_matches_total",
			Help: "Total number of matched WAF rules that carry the log action.",
		},
		[]string{"tenant", "rule_id"},
	)

	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "synit_waf_build_info",
			Help: "Build information; the value is always 1.",
		},
		[]string{"version", "goversion"},
	)

	logForwardDroppedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "synit_waf_log_forward_dropped_total",
			Help: "Total log events dropped because of size, queue saturation, or delivery failure.",
		},
	)
)

func init() {
	prometheus.MustRegister(requestTotal)
	prometheus.MustRegister(blockedTotal)
	prometheus.MustRegister(upstreamHealthy)
	prometheus.MustRegister(configReloadTotal)
	prometheus.MustRegister(auditModeEventsTotal)
	prometheus.MustRegister(logForwardDroppedTotal)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(upstreamRequestsTotal)
	prometheus.MustRegister(ruleMatchesTotal)
	prometheus.MustRegister(buildInfo)
	buildInfo.WithLabelValues(Version, runtime.Version()).Set(1)
}
