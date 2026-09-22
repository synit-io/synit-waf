package waf

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	maxAccessLogFieldBytes = 2048
	devBypassHeader        = "X-Synit-Dev-Bypass"
)

// devBypassGranted reports whether the request carries the tenant's
// development bypass secret. The comparison is constant time.
func devBypassGranted(r *http.Request, secret string) bool {
	if secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get(devBypassHeader)), []byte(secret)) == 1
}

// ServeHTTP is the main entry point for incoming requests.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	trustedProxies := h.trustedProxies()
	trustForwarded := h.trustForwardedFor.Load()
	clientIP := clientIPFromRequest(r, trustForwarded, trustedProxies)
	ipAddr, _ := netip.ParseAddr(clientIP)

	// Resolve the tenant once; every later stage reads it from the request.
	entry, matchedDomain, matched := h.registry.Get(r.Host)
	info := &requestInfo{clientIP: clientIP, tenant: matchedDomain, entry: entry, matched: matched}
	if trustForwarded {
		if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && prefixesContain(trustedProxies, peer.Addr().Unmap()) {
			info.trustedPeer = true
			info.forwardedHost = r.Header.Get("X-Forwarded-Host")
			info.forwardedProt = r.Header.Get("X-Forwarded-Proto")
		}
	}
	r = withRequestInfo(r, info)

	lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	tenantMetric := "unmatched"
	if matched {
		tenantMetric = matchedDomain
	}

	// The defer logs the request also when a later stage panics.
	defer func() {
		if recovered := recover(); recovered != nil {
			// ReverseProxy aborts a broken response with ErrAbortHandler;
			// net/http must see that value to close the connection quietly.
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}
			ErrorLog.WithFields(logrus.Fields{
				"client_ip": clientIP,
				"host":      boundedLogValue(r.Host),
				"path":      boundedLogValue(r.URL.Path),
			}).Errorf("panic while serving request: %v\n%s", recovered, debug.Stack())
			if !lw.wroteHeader {
				http.Error(lw, "Internal Server Error", http.StatusInternalServerError)
			} else {
				lw.statusCode = http.StatusInternalServerError
			}
		}

		duration := time.Since(start)
		writeAccessLog(accessLogRecord{
			clientIP:  clientIP,
			method:    r.Method,
			host:      r.Host,
			path:      r.URL.Path,
			proto:     r.Proto,
			status:    lw.statusCode,
			size:      lw.size,
			duration:  duration,
			referer:   r.Header.Get("Referer"),
			userAgent: r.Header.Get("User-Agent"),
			tenant:    tenantMetric,
			user:      info.user,
		})
		requestTotal.WithLabelValues(tenantMetric, statusClassLabel(lw.statusCode)).Inc()
		requestDuration.WithLabelValues(tenantMetric).Observe(duration.Seconds())
	}()

	// 1. Global IP block list
	if blockList := h.blockIPs.Load(); blockList != nil && prefixesContain(*blockList, ipAddr) {
		blockedTotal.WithLabelValues("ip_blocklist", "global").Inc()
		lw.Header().Set("Content-Type", "application/json")
		lw.WriteHeader(http.StatusForbidden)
		_, _ = lw.Write([]byte(`{"error": "Forbidden", "message": "IP is blocked"}`))
		return
	}

	allowlisted := false
	if allowList := h.allowIPs.Load(); allowList != nil {
		allowlisted = prefixesContain(*allowList, ipAddr)
	}

	// 2. Country policy using the configured MaxMind database.
	geoIPEnabled := matched && entry.Tenant.Security.GeoIPEnabled != nil && *entry.Tenant.Security.GeoIPEnabled
	if !allowlisted && geoIPEnabled {
		country, found, err := h.lookupCountry(ipAddr)
		switch {
		case err != nil:
			if !errors.Is(err, errGeoIPUnavailable) {
				ErrorLog.WithField("client_ip", clientIP).Errorf("GeoIP lookup failed: %v", err)
			}
			if h.getDependencyFailMode() == dependencyFailClosed {
				http.Error(lw, "Security dependency unavailable", http.StatusServiceUnavailable)
				return
			}
		case found && slices.Contains(entry.Tenant.Security.BlockedCountries, country):
			blockedTotal.WithLabelValues("geoip", matchedDomain).Inc()
			http.Error(lw, "Forbidden: country is blocked", http.StatusForbidden)
			return
		}
	}

	// 3. Global rate limiting
	if !allowlisted {
		if limiter := h.globalLimiter.Load(); limiter != nil {
			if !limiter.Allow() {
				blockedTotal.WithLabelValues("global_rate_limit", "global").Inc()
				http.Error(lw, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
	}

	// 4. Enforce FQDN allow-listing
	if !matched {
		// Scanners probe arbitrary hosts, so this message is rate limited.
		h.unknownHostLog.Do(func() {
			ErrorLog.WithFields(logrus.Fields{"client_ip": clientIP, "host": boundedLogValue(r.Host)}).Warn("Blocked attempt to access unconfigured host")
		})
		blockedTotal.WithLabelValues("unknown_host", "unmatched").Inc()
		http.Error(lw, "Forbidden: Access to this host is not allowed", http.StatusForbidden)
		return
	}
	tenant := entry.Tenant

	// 5. Per-tenant request rate limiting.
	if !allowlisted {
		if !h.allowRateLimitedRequest(matchedDomain, clientIP, tenant.Security.RateLimit) {
			blockedTotal.WithLabelValues("rate_limit", matchedDomain).Inc()
			http.Error(lw, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// 6. Per-Tenant Edge JWT Validation
	if tenant.Security.JWTValidation.Enabled {
		if !h.validateJWT(lw, r, tenant.Security.JWTValidation) {
			return
		}
	}

	// 7. Per-Tenant Basic Auth Check
	if len(tenant.Security.BasicAuth) > 0 {
		var authed bool
		authed, r = h.checkBasicAuth(r, tenant.Security.BasicAuth) // Update request with new context
		if !authed {
			ErrorLog.WithFields(logrus.Fields{"client_ip": clientIP, "host": boundedLogValue(r.Host)}).Info("Failed basic auth attempt")
			blockedTotal.WithLabelValues("basic_auth", matchedDomain).Inc()
			lw.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(lw, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 8. Per-Tenant CrowdSec IP Check
	if tenant.Security.CrowdSecEnabled != nil && *tenant.Security.CrowdSecEnabled {
		bouncer := h.bouncer.Load()
		if bouncer == nil {
			if h.getDependencyFailMode() == dependencyFailClosed {
				blockedTotal.WithLabelValues("crowdsec_unavailable", matchedDomain).Inc()
				http.Error(lw, "Security dependency unavailable", http.StatusServiceUnavailable)
				return
			}
			ErrorLog.WithField("tenant", matchedDomain).Warn("CrowdSec enabled but bouncer is not initialized; allowing request in fail-open mode")
		} else {
			banned, err := h.crowdSecBanned(r.Context(), bouncer, clientIP)
			if err != nil {
				ErrorLog.WithField("client_ip", clientIP).Errorf("Failed to check IP with CrowdSec: %v", err)
				if h.getDependencyFailMode() == dependencyFailClosed {
					blockedTotal.WithLabelValues("crowdsec_error", matchedDomain).Inc()
					http.Error(lw, "Security dependency unavailable", http.StatusServiceUnavailable)
					return
				}
			}
			if banned {
				ErrorLog.WithField("client_ip", clientIP).Info("CrowdSec: Denying banned IP")
				blockedTotal.WithLabelValues("crowdsec", matchedDomain).Inc()
				lw.Header().Set("Content-Type", "application/json")
				lw.WriteHeader(http.StatusForbidden)
				_, _ = lw.Write([]byte(`{"error": "Blocked by Security Policy"}`))
				return
			}
		}
	}

	// 9. Content inspection: Coraza, GraphQL, LLM. The development bypass
	// skips these three controls only.
	if !allowlisted {
		if devBypassGranted(r, tenant.Security.DevBypassSecret) {
			ErrorLog.WithFields(logrus.Fields{"client_ip": clientIP, "host": boundedLogValue(r.Host)}).Info("WAF bypassed due to dev mode secret")
		} else {
			// entry.WAF is not nil only if waf_enabled was true for the tenant
			if entry.WAF != nil && h.applyWAF(lw, r, entry.WAF) {
				return
			}
			if tenant.Security.GraphQL.Enabled && h.applyGraphQLProtection(lw, r, tenant.Security.GraphQL) {
				return
			}
			if tenant.Security.LLMProtection.Enabled && h.applyLLMProtection(lw, r, tenant.Security.LLMProtection) {
				return
			}
		}
	}

	// 10. Proxy the request with load balancing
	state, ok := h.tenantStates.Load(matchedDomain)
	if !ok {
		ErrorLog.WithFields(logrus.Fields{"client_ip": clientIP, "host": boundedLogValue(r.Host), "matched_domain": matchedDomain}).Error("No backend configured for host")
		http.Error(lw, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	tenantState := state.(*TenantState)

	upstream := tenantState.selectUpstream()
	if upstream == nil {
		ErrorLog.WithFields(logrus.Fields{"client_ip": clientIP, "host": boundedLogValue(r.Host)}).Error("No healthy upstream available")
		lw.Header().Set("Content-Type", "application/json")
		lw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = lw.Write([]byte(`{"error": "Service Unavailable", "message": "No healthy upstreams available"}`))
		return
	}

	// Request header transformation and forwarding headers are applied in the
	// upstream's Rewrite hook, after hop-by-hop headers are removed.
	upstream.Proxy.ServeHTTP(lw, r)
}

var errGeoIPUnavailable = fmt.Errorf("GeoIP database is not loaded")

// lookupCountry holds the GeoIP read lock only for the in-memory lookup.
func (h *ProxyHandler) lookupCountry(addr netip.Addr) (string, bool, error) {
	h.geoMu.RLock()
	defer h.geoMu.RUnlock()
	if h.geoIP == nil {
		return "", false, errGeoIPUnavailable
	}
	return h.geoIP.LookupCountry(addr)
}

func boundedLogValue(value string) string {
	if len(value) <= maxAccessLogFieldBytes {
		return value
	}
	return value[:maxAccessLogFieldBytes]
}

func clientIPFromRequest(r *http.Request, trustForwarded bool, trustedProxies []netip.Prefix) string {
	peerIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerIP = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(peerIP)
	if err != nil {
		return peerIP
	}
	peer = peer.Unmap()
	if !trustForwarded || !prefixesContain(trustedProxies, peer) {
		return peer.String()
	}

	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for _, part := range slices.Backward(parts) {
		candidate, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return peer.String()
		}
		candidate = candidate.Unmap()
		if !prefixesContain(trustedProxies, candidate) {
			return candidate.String()
		}
	}
	return peer.String()
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
