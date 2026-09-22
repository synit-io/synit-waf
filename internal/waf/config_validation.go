package waf

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	oversizeActionReject = "reject"
	dependencyFailOpen   = "fail_open"
	dependencyFailClosed = "fail_closed"
)

func normalizeOversizeAction(action string) string {
	normalized := strings.ToLower(strings.TrimSpace(action))
	if normalized == "" {
		return oversizeActionReject
	}
	return normalized
}

func normalizeDependencyFailMode(mode string) string {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	if normalized == "" {
		return dependencyFailOpen
	}
	return normalized
}

func validateServiceURL(name, raw string, allowInsecure bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s must be a valid URL: %w", name, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not contain user credentials", name)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("%s must include a host", name)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" {
		return fmt.Errorf("%s must use http or https", name)
	}
	if allowInsecure || strings.EqualFold(parsed.Hostname(), "localhost") {
		return nil
	}
	if addr, err := netip.ParseAddr(parsed.Hostname()); err == nil && addr.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s must use https outside loopback; set global_settings.allow_insecure_service_urls only for a trusted private network", name)
}

// ValidateConfig performs a comprehensive validation of the application configuration.
// It checks for duplicate domains, invalid rule sets, and other security invariants.
func ValidateConfig(cfg AppConfig) error {
	action := normalizeOversizeAction(cfg.GlobalSettings.OversizeAction)
	if action != oversizeActionReject {
		return fmt.Errorf("global_settings.request_body_oversize_action must be %s", oversizeActionReject)
	}

	failMode := normalizeDependencyFailMode(cfg.GlobalSettings.DependencyFailMode)
	if failMode != dependencyFailOpen && failMode != dependencyFailClosed {
		return fmt.Errorf("global_settings.security_dependency_failure_mode must be one of [%s, %s]", dependencyFailOpen, dependencyFailClosed)
	}
	adminAddress := cfg.GlobalSettings.AdminAddress
	if adminAddress == "" {
		adminAddress = "127.0.0.1:9090"
	}
	if _, _, err := net.SplitHostPort(adminAddress); err != nil {
		return fmt.Errorf("global_settings.admin_address must be host:port: %w", err)
	}

	if cfg.GlobalSettings.GlobalRateLimit.RequestsPerMinute < 0 {
		return fmt.Errorf("global_settings.global_rate_limit.requests_per_minute must be >= 0")
	}
	if cfg.GlobalSettings.GlobalRateLimit.Burst < 0 {
		return fmt.Errorf("global_settings.global_rate_limit.burst must be >= 0")
	}
	if cfg.GlobalSettings.GlobalRateLimit.RequestsPerMinute > 0 && cfg.GlobalSettings.GlobalRateLimit.Burst == 0 {
		return fmt.Errorf("global_settings.global_rate_limit.burst must be > 0 when global rate limiting is enabled")
	}
	if cfg.GlobalSettings.ReadTimeout < 0 || cfg.GlobalSettings.WriteTimeout < 0 || cfg.GlobalSettings.IdleTimeout < 0 {
		return fmt.Errorf("global_settings HTTP timeouts must be non-negative")
	}
	if cfg.GlobalSettings.RequestBodyLimit < 0 || cfg.GlobalSettings.ResponseMaskingLimit < 0 {
		return fmt.Errorf("global_settings.request_body_limit and response_masking_limit must be non-negative")
	}
	if cfg.GlobalSettings.UpstreamTransport.MaxIdleConnsPerHost < 0 || cfg.GlobalSettings.UpstreamTransport.MaxConnsPerHost < 0 {
		return fmt.Errorf("global_settings.upstream_transport limits must be non-negative")
	}
	if cfg.CrowdSec.CacheTTL != nil && *cfg.CrowdSec.CacheTTL < 0 {
		return fmt.Errorf("crowdsec.cache_ttl must be non-negative")
	}
	if cfg.GlobalSettings.Coordinator.Enabled {
		if cfg.GlobalSettings.Coordinator.Role != "leader" && cfg.GlobalSettings.Coordinator.Role != "follower" {
			return fmt.Errorf("global_settings.coordinator.role must be leader or follower")
		}
		if _, _, err := net.SplitHostPort(cfg.GlobalSettings.Coordinator.Address); err != nil {
			return fmt.Errorf("global_settings.coordinator.address must be host:port: %w", err)
		}
		if strings.TrimSpace(cfg.GlobalSettings.Coordinator.Secret) == "" {
			return fmt.Errorf("global_settings.coordinator.secret is required when coordinator is enabled")
		}
		tlsConfig := cfg.GlobalSettings.Coordinator.TLS
		if cfg.GlobalSettings.Coordinator.Role == "leader" && (strings.TrimSpace(tlsConfig.CAFile) == "" || strings.TrimSpace(tlsConfig.CertFile) == "" || strings.TrimSpace(tlsConfig.KeyFile) == "") {
			return fmt.Errorf("global_settings.coordinator.tls ca_file, cert_file, and key_file are required for a leader")
		}
		if cfg.GlobalSettings.Coordinator.Role == "follower" && (strings.TrimSpace(tlsConfig.CAFile) == "" || strings.TrimSpace(tlsConfig.CertFile) == "" || strings.TrimSpace(tlsConfig.KeyFile) == "" || strings.TrimSpace(tlsConfig.ServerName) == "") {
			return fmt.Errorf("global_settings.coordinator.tls ca_file, cert_file, key_file, and server_name are required for a follower")
		}
	}
	for _, set := range []struct {
		name    string
		entries []string
	}{
		{name: "allow_list", entries: cfg.GlobalSettings.IPSets.AllowList},
		{name: "block_list", entries: cfg.GlobalSettings.IPSets.BlockList},
		{name: "trusted_proxy_cidrs", entries: cfg.GlobalSettings.TrustedProxyCIDRs},
	} {
		for _, entry := range set.entries {
			if _, err := netip.ParsePrefix(entry); err != nil {
				if _, addrErr := netip.ParseAddr(entry); addrErr != nil {
					return fmt.Errorf("global_settings.ip_sets.%s contains invalid IP or CIDR %q", set.name, entry)
				}
			}
		}
	}
	if cfg.GlobalSettings.TrustForwardedFor && len(cfg.GlobalSettings.TrustedProxyCIDRs) == 0 {
		return fmt.Errorf("global_settings.trusted_proxy_cidrs is required when trust_forwarded_for is true")
	}

	if cfg.GlobalSettings.ACME.Enabled {
		if strings.TrimSpace(cfg.GlobalSettings.ACME.Email) == "" {
			return fmt.Errorf("global_settings.acme.email is required when acme is enabled")
		}
		if !cfg.GlobalSettings.ACME.AgreeTOS {
			return fmt.Errorf("global_settings.acme.agree_tos must be true: read the certificate authority's subscriber agreement and accept it explicitly")
		}
		provider := strings.ToLower(strings.TrimSpace(cfg.GlobalSettings.ACME.DNSProvider))
		if provider != "" && provider != "cloudflare" {
			return fmt.Errorf("global_settings.acme.dns_provider must be empty or cloudflare")
		}
		if provider == "cloudflare" && strings.TrimSpace(cfg.GlobalSettings.ACME.DNSToken) == "" {
			return fmt.Errorf("global_settings.acme.dns_token is required for cloudflare")
		}
	}
	for _, sink := range []struct {
		name    string
		enabled bool
		path    string
		format  string
	}{
		{name: "logging.access_log", enabled: cfg.Logging.AccessLog.Enabled, path: cfg.Logging.AccessLog.Path, format: cfg.Logging.AccessLog.Format},
		{name: "logging.error_log", enabled: cfg.Logging.ErrorLog.Enabled, path: cfg.Logging.ErrorLog.Path, format: cfg.Logging.ErrorLog.Format},
	} {
		if !sink.enabled {
			continue
		}
		if strings.TrimSpace(sink.path) == "" {
			return fmt.Errorf("%s.path is required when enabled", sink.name)
		}
		format := strings.ToLower(strings.TrimSpace(sink.format))
		if format != "json" && format != "text" {
			return fmt.Errorf("%s.format must be json or text", sink.name)
		}
	}
	if cfg.Logging.LogForwarder.Enabled {
		if strings.TrimSpace(cfg.Logging.LogForwarder.Token) == "" {
			return fmt.Errorf("logging.log_forwarder.token is required when forwarding is enabled")
		}
		if err := validateServiceURL("logging.log_forwarder.url", cfg.Logging.LogForwarder.URL, cfg.GlobalSettings.AllowInsecureServiceURLs); err != nil {
			return err
		}
	}

	if len(cfg.Tenants) == 0 {
		return fmt.Errorf("at least one tenant must be configured")
	}

	normalizedHosts := make(map[string]string, len(cfg.Tenants))

	for fqdn, tenant := range cfg.Tenants {
		normalizedHost := normalizeHost(fqdn)
		if normalizedHost == "" {
			return fmt.Errorf("tenant host key cannot be empty")
		}
		if strings.Contains(normalizedHost, "*") && !strings.HasPrefix(normalizedHost, "*.") {
			return fmt.Errorf("tenant %s has unsupported wildcard syntax; only leading '*.' is allowed", fqdn)
		}
		if cfg.GlobalSettings.ACME.Enabled && strings.HasPrefix(normalizedHost, "*.") &&
			!strings.EqualFold(strings.TrimSpace(cfg.GlobalSettings.ACME.DNSProvider), "cloudflare") {
			return fmt.Errorf("tenant %s requires ACME DNS provider cloudflare for wildcard certificates", fqdn)
		}
		if originalHost, exists := normalizedHosts[normalizedHost]; exists {
			return fmt.Errorf("tenant host %s collides with %s after normalization", fqdn, originalHost)
		}
		normalizedHosts[normalizedHost] = fqdn

		if len(tenant.Upstreams) == 0 {
			return fmt.Errorf("tenant %s must define at least one upstream", fqdn)
		}

		for _, upstream := range tenant.Upstreams {
			target, err := url.Parse(strings.TrimSpace(upstream.URL))
			if err != nil {
				return fmt.Errorf("tenant %s has invalid upstream %q: %w", fqdn, upstream.URL, err)
			}
			if target.Scheme != "http" && target.Scheme != "https" {
				return fmt.Errorf("tenant %s upstream %q must use http or https", fqdn, upstream.URL)
			}
			if target.Host == "" {
				return fmt.Errorf("tenant %s upstream %q is missing host", fqdn, upstream.URL)
			}
			if target.User != nil {
				return fmt.Errorf("tenant %s upstream %q must not contain user credentials", fqdn, target.Redacted())
			}
			if upstream.ResponseHeaderTimeout < 0 {
				return fmt.Errorf("tenant %s upstream %q response_header_timeout must be non-negative", fqdn, target.Redacted())
			}
		}
		if tenant.HealthCheck.Interval < 0 || tenant.HealthCheck.Timeout < 0 {
			return fmt.Errorf("tenant %s health_check interval and timeout must be non-negative", fqdn)
		}
		if tenant.HealthCheck.Path != "" {
			if err := validateInspectionPaths("health_check.path", []string{tenant.HealthCheck.Path}); err != nil {
				return fmt.Errorf("tenant %s %w", fqdn, err)
			}
		}
		if secret := tenant.Security.DevBypassSecret; secret != "" && len(secret) < minDevBypassSecretBytes {
			return fmt.Errorf("tenant %s dev_bypass_secret must be at least %d characters", fqdn, minDevBypassSecretBytes)
		}
		if path := tenant.Security.BlockPagePath; path != "" {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("tenant %s block_page_path: %w", fqdn, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("tenant %s block_page_path %s is not a regular file", fqdn, path)
			}
		}

		if tenant.Security.WAFEnabled != nil && *tenant.Security.WAFEnabled {
			if tenant.Security.ParanoiaLevel < 1 || tenant.Security.ParanoiaLevel > 4 {
				return fmt.Errorf("tenant %s paranoia_level must be between 1 and 4 when waf_enabled is true", fqdn)
			}
			for _, setName := range tenant.Security.IncludeRuleSets {
				if _, ok := cfg.WAFRuleSets[setName]; !ok {
					return fmt.Errorf("tenant %s references unknown waf_rule_set %q", fqdn, setName)
				}
			}
		}

		if tenant.Security.CrowdSecEnabled != nil && *tenant.Security.CrowdSecEnabled {
			if strings.TrimSpace(cfg.CrowdSec.APIUrl) == "" || strings.TrimSpace(cfg.CrowdSec.APIKey) == "" {
				return fmt.Errorf("tenant %s enables crowdsec but crowdsec.api_url/api_key are not both configured", fqdn)
			}
			if err := validateServiceURL("crowdsec.api_url", cfg.CrowdSec.APIUrl, cfg.GlobalSettings.AllowInsecureServiceURLs); err != nil {
				return err
			}
		}

		if tenant.Security.GeoIPEnabled != nil && *tenant.Security.GeoIPEnabled {
			if strings.TrimSpace(cfg.GeoIP.DBPath) == "" {
				return fmt.Errorf("tenant %s enables geoip but geoip.db_path is empty", fqdn)
			}
			if len(tenant.Security.BlockedCountries) == 0 {
				return fmt.Errorf("tenant %s enables geoip but blocked_countries is empty", fqdn)
			}
			for _, country := range tenant.Security.BlockedCountries {
				country = strings.ToUpper(strings.TrimSpace(country))
				if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
					return fmt.Errorf("tenant %s has invalid ISO country code %q", fqdn, country)
				}
			}
		}

		if tenant.Security.JWTValidation.Enabled && len(tenant.Security.BasicAuth) > 0 {
			return fmt.Errorf("tenant %s cannot combine jwt_validation and basic_auth: both read the Authorization header", fqdn)
		}
		if tenant.Security.JWTValidation.Enabled {
			if strings.TrimSpace(tenant.Security.JWTValidation.JWKSEndpoint) == "" {
				return fmt.Errorf("tenant %s enables jwt_validation but jwks_endpoint is empty", fqdn)
			}
			if strings.TrimSpace(tenant.Security.JWTValidation.Issuer) == "" || strings.TrimSpace(tenant.Security.JWTValidation.Audience) == "" {
				return fmt.Errorf("tenant %s jwt_validation issuer and audience are required", fqdn)
			}
			if err := validateServiceURL("tenant "+fqdn+" jwt_validation.jwks_endpoint", tenant.Security.JWTValidation.JWKSEndpoint, cfg.GlobalSettings.AllowInsecureServiceURLs); err != nil {
				return err
			}
		}

		for _, cred := range tenant.Security.BasicAuth {
			if strings.TrimSpace(cred.User) == "" {
				return fmt.Errorf("tenant %s has a basic_auth entry with empty user", fqdn)
			}
			if strings.TrimSpace(cred.Password) == "" {
				return fmt.Errorf("tenant %s basic_auth user %q has an empty password hash", fqdn, cred.User)
			}
			if _, err := bcrypt.Cost([]byte(cred.Password)); err != nil {
				return fmt.Errorf("tenant %s basic_auth user %q must use bcrypt password hashes: %w", fqdn, cred.User, err)
			}
		}

		for _, rule := range tenant.Security.ResponseMasking {
			if strings.TrimSpace(rule.Pattern) == "" {
				return fmt.Errorf("tenant %s has empty response_masking pattern", fqdn)
			}
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("tenant %s has invalid response_masking pattern %q: %v", fqdn, rule.Pattern, err)
			}
		}
		if len(tenant.Security.ResponseMasking) > 0 {
			for _, key := range tenant.HeaderTransform.StripResponse {
				if isRepresentationHeader(key) {
					return fmt.Errorf("tenant %s cannot strip response header %s while response masking is enabled", fqdn, key)
				}
			}
			for key := range tenant.HeaderTransform.InjectResponse {
				if isRepresentationHeader(key) {
					return fmt.Errorf("tenant %s cannot inject response header %s while response masking is enabled", fqdn, key)
				}
			}
		}

		if tenant.Security.RateLimit.RequestsPerMinute < 0 {
			return fmt.Errorf("tenant %s rate_limit.requests_per_minute must be >= 0", fqdn)
		}
		if tenant.Security.RateLimit.Burst < 0 {
			return fmt.Errorf("tenant %s rate_limit.burst must be >= 0", fqdn)
		}
		if tenant.Security.RateLimit.RequestsPerMinute > 0 && tenant.Security.RateLimit.Burst == 0 {
			return fmt.Errorf("tenant %s rate_limit.burst must be > 0 when rate limiting is enabled", fqdn)
		}
		if tenant.Security.RateLimit.RequestsPerMinute == 0 && tenant.Security.RateLimit.Burst > 0 {
			return fmt.Errorf("tenant %s rate_limit.requests_per_minute must be > 0 when burst is set", fqdn)
		}
		if tenant.Security.CircuitBreaker.Enabled {
			if tenant.Security.CircuitBreaker.Threshold <= 0 {
				return fmt.Errorf("tenant %s circuit_breaker.threshold must be positive", fqdn)
			}
			if tenant.Security.CircuitBreaker.Cooldown < 0 {
				return fmt.Errorf("tenant %s circuit_breaker.cooldown must be non-negative", fqdn)
			}
			for _, status := range tenant.Security.CircuitBreaker.FailureStatusCodes {
				if status < 400 || status > 599 {
					return fmt.Errorf("tenant %s circuit_breaker.failure_status_codes must contain only HTTP 400..599", fqdn)
				}
			}
		}

		if tenant.Security.GraphQL.Enabled {
			if tenant.Security.GraphQL.MaxQueryDepth < 0 {
				return fmt.Errorf("tenant %s graphql.max_query_depth must be >= 0", fqdn)
			}
			if tenant.Security.GraphQL.MaxBatchedQueries < 0 {
				return fmt.Errorf("tenant %s graphql.max_batched_queries must be >= 0", fqdn)
			}
			if tenant.Security.GraphQL.MaxQueryBytes < 0 {
				return fmt.Errorf("tenant %s graphql.max_query_bytes must be >= 0", fqdn)
			}
			if err := validateInspectionPaths("graphql.paths", tenant.Security.GraphQL.Paths); err != nil {
				return fmt.Errorf("tenant %s %w", fqdn, err)
			}
		}

		// The built-in llm-protection rules embed inspect_paths, so the paths
		// are checked even when the ML layer is disabled.
		if err := validateInspectionPaths("llm_protection.inspect_paths", tenant.Security.LLMProtection.InspectPaths); err != nil {
			return fmt.Errorf("tenant %s %w", fqdn, err)
		}
		if tenant.Security.LLMProtection.Enabled {
			llm := tenant.Security.LLMProtection
			if llm.Mode != "rules" && llm.Mode != "ml" && llm.Mode != "hybrid" {
				return fmt.Errorf("tenant %s llm_protection.mode must be one of [rules, ml, hybrid]", fqdn)
			}
			if llm.Action != "deny" && llm.Action != "audit" {
				return fmt.Errorf("tenant %s llm_protection.action must be one of [deny, audit]", fqdn)
			}
			if llm.FailMode != "open" && llm.FailMode != "closed" {
				return fmt.Errorf("tenant %s llm_protection.fail_mode must be one of [open, closed]", fqdn)
			}
			if math.IsNaN(llm.Threshold) || math.IsInf(llm.Threshold, 0) || llm.Threshold < 0.0 || llm.Threshold > 1.0 {
				return fmt.Errorf("tenant %s llm_protection.threshold must be between 0.0 and 1.0", fqdn)
			}
			if llm.Timeout <= 0 {
				return fmt.Errorf("tenant %s llm_protection.timeout must be positive", fqdn)
			}
			if llm.MaxTextBytes <= 0 {
				return fmt.Errorf("tenant %s llm_protection.max_text_bytes must be positive", fqdn)
			}
			if llm.MaxBodyBytes < 0 {
				return fmt.Errorf("tenant %s llm_protection.max_body_bytes must be >= 0", fqdn)
			}
			if llm.SidecarMaxBatch <= 0 {
				return fmt.Errorf("tenant %s llm_protection.sidecar_max_batch must be positive", fqdn)
			}
			if llm.Mode == "ml" || llm.Mode == "hybrid" {
				if llm.SidecarURL == "" {
					return fmt.Errorf("tenant %s llm_protection enables ml/hybrid but sidecar_url is empty", fqdn)
				}
				if strings.TrimSpace(llm.SidecarToken) == "" {
					return fmt.Errorf("tenant %s llm_protection enables ml/hybrid but sidecar_token is empty", fqdn)
				}
				if err := validateServiceURL("tenant "+fqdn+" llm_protection.sidecar_url", llm.SidecarURL, cfg.GlobalSettings.AllowInsecureServiceURLs); err != nil {
					return err
				}
			}
			if llm.Mode == "rules" || llm.Mode == "hybrid" {
				if tenant.Security.WAFEnabled == nil || !*tenant.Security.WAFEnabled {
					return fmt.Errorf("tenant %s llm_protection mode %s requires waf_enabled", fqdn, llm.Mode)
				}
				if !slices.Contains(tenant.Security.IncludeRuleSets, "llm-protection") {
					return fmt.Errorf("tenant %s llm_protection mode %s requires the llm-protection rule set", fqdn, llm.Mode)
				}
			}
		}
	}

	return nil
}

// validateInspectionPaths requires absolute URL paths without characters that
// would need escaping inside a generated SecLang rule.
func validateInspectionPaths(name string, paths []string) error {
	for _, path := range paths {
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("%s entry %q must start with /", name, path)
		}
		if strings.ContainsFunc(path, func(r rune) bool {
			return r == '"' || r == '\'' || r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			return fmt.Errorf("%s entry %q must not contain quotes, backslashes, whitespace, or control characters", name, path)
		}
	}
	return nil
}

func isRepresentationHeader(key string) bool {
	switch http.CanonicalHeaderKey(strings.TrimSpace(key)) {
	case "Content-Type", "Content-Encoding", "Content-Length", "Content-Range", "Accept-Ranges", "Etag", "Last-Modified":
		return true
	default:
		return false
	}
}
