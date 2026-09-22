package waf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

var (
	// Version is the current version of the WAF.
	// This should be set during build using -ldflags "-X 'github.com/synit-io/synit-waf/internal/waf.Version=v1.0.0'"
	Version = "dev"
)

// Synit WAF reserves rule IDs 440000-440099 for its built-in directives so
// they cannot collide with OWASP CRS (900000-999999) or operator rules.
const (
	paranoiaRuleID        = 440000
	requestBodyErrorRule  = `SecRule REQBODY_ERROR "!@eq 0" "id:440001,phase:2,deny,status:403,log,msg:'Request body parsing failed'"`
	defaultRulesDir       = "/etc/waf/rules"
	defaultRequestBodyCap = 1048576
	llmRuleSetName        = "llm-protection"

	defaultUpstreamMaxIdleConnsPerHost = 64
	defaultCrowdSecCacheTTL            = 30 * time.Second
	defaultHealthCheckInterval         = 10 * time.Second
	defaultHealthCheckTimeout          = 5 * time.Second
	minDevBypassSecretBytes            = 32
)

// BasicAuthCredentials holds a single user/password pair.
type BasicAuthCredentials struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

// RateLimitPolicy defines per-tenant request throttling.
type RateLimitPolicy struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst             int `yaml:"burst"`
}

// ResponseMaskingRule defines a regex pattern and replacement for response body scrubbing.
type ResponseMaskingRule struct {
	Pattern         string         `yaml:"pattern"`
	Replacement     string         `yaml:"replacement"`
	CompiledPattern *regexp.Regexp `yaml:"-"`
}

// GraphQLProtection defines limits and rules for GraphQL endpoints.
type GraphQLProtection struct {
	Enabled            bool     `yaml:"enabled"`
	Paths              []string `yaml:"paths"`
	BlockIntrospection bool     `yaml:"block_introspection"`
	MaxQueryDepth      int      `yaml:"max_query_depth"`
	MaxBatchedQueries  int      `yaml:"max_batched_queries"`
	MaxQueryBytes      int      `yaml:"max_query_bytes"`
}

// JWTValidationConfig defines edge validation of bearer tokens.
type JWTValidationConfig struct {
	Enabled      bool   `yaml:"enabled"`
	JWKSEndpoint string `yaml:"jwks_endpoint"`
	Issuer       string `yaml:"issuer"`
	Audience     string `yaml:"audience"`
}

// HealthCheckConfig defines active upstream health checks.
// An empty Path selects a TCP connect check; otherwise an HTTP GET is used.
type HealthCheckConfig struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Path     string        `yaml:"path"`
}

// LLMProtectionConfig defines configuration for protecting LLM endpoints.
type LLMProtectionConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Mode              string        `yaml:"mode"`   // rules | ml | hybrid
	Action            string        `yaml:"action"` // deny | audit
	Threshold         float64       `yaml:"threshold"`
	FailMode          string        `yaml:"fail_mode"` // open | closed
	Timeout           time.Duration `yaml:"timeout"`
	MaxBodyBytes      int           `yaml:"max_body_bytes"`
	MaxTextBytes      int           `yaml:"max_text_bytes"`
	SidecarMaxBatch   int           `yaml:"sidecar_max_batch"`
	SidecarURL        string        `yaml:"sidecar_url"`
	SidecarToken      string        `yaml:"sidecar_token"`
	SidecarTokenEnv   string        `yaml:"sidecar_token_env"`
	InspectPaths      []string      `yaml:"inspect_paths"`
	InspectJSONFields []string      `yaml:"inspect_json_fields"`
}

// SecurityPolicy defines the security features to be applied to a tenant.
type SecurityPolicy struct {
	WAFEnabled       *bool                  `yaml:"waf_enabled"`
	AuditMode        bool                   `yaml:"audit_mode"`
	ParanoiaLevel    int                    `yaml:"paranoia_level"`
	CrowdSecEnabled  *bool                  `yaml:"crowdsec_enabled"`
	GeoIPEnabled     *bool                  `yaml:"geoip_enabled"`
	BlockedCountries []string               `yaml:"blocked_countries"`
	IncludeRuleSets  []string               `yaml:"include_rule_sets"`
	CustomRules      string                 `yaml:"custom_rules"`
	BlockPageURL     string                 `yaml:"block_page_url"`
	BlockPagePath    string                 `yaml:"block_page_path"`
	JWTValidation    JWTValidationConfig    `yaml:"jwt_validation"`
	DevBypassSecret  string                 `yaml:"dev_bypass_secret"`
	BasicAuth        []BasicAuthCredentials `yaml:"basic_auth"`
	RateLimit        RateLimitPolicy        `yaml:"rate_limit"`
	ResponseMasking  []ResponseMaskingRule  `yaml:"response_masking"`
	GraphQL          GraphQLProtection      `yaml:"graphql"`
	LLMProtection    LLMProtectionConfig    `yaml:"llm_protection"`
	CircuitBreaker   struct {
		Enabled            bool          `yaml:"enabled"`
		Threshold          int           `yaml:"threshold"`
		Cooldown           time.Duration `yaml:"cooldown"`
		FailureStatusCodes []int         `yaml:"failure_status_codes"`
	} `yaml:"circuit_breaker"`
}

// Upstream defines a single upstream server.
type Upstream struct {
	URL                   string        `yaml:"url"`
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout"`
}

// HeaderTransform defines transformations to be applied to request and response headers.
type HeaderTransform struct {
	InjectRequest  map[string]string `yaml:"inject_request"`
	StripRequest   []string          `yaml:"strip_request"`
	InjectResponse map[string]string `yaml:"inject_response"`
	StripResponse  []string          `yaml:"strip_response"`
}

// Tenant defines the configuration for a single FQDN.
type Tenant struct {
	Upstreams        []Upstream        `yaml:"upstreams,omitempty"`
	UpstreamInsecure *bool             `yaml:"upstreamInsecure"`
	HealthCheck      HealthCheckConfig `yaml:"health_check"`
	HeaderTransform  HeaderTransform   `yaml:"header_transform"`
	Security         SecurityPolicy    `yaml:"security"`
}

// AppConfig is the root configuration structure.
type AppConfig struct {
	GlobalSettings struct {
		LogLevel         string `yaml:"log_level"`
		RequestBodyLimit int64  `yaml:"request_body_limit"`
		// ResponseBufferLimit is the deprecated name of RequestBodyLimit.
		ResponseBufferLimit      int64         `yaml:"response_buffer_limit"`
		ResponseMaskingLimit     int64         `yaml:"response_masking_limit"`
		RulesDir                 string        `yaml:"rules_dir"`
		OversizeAction           string        `yaml:"request_body_oversize_action"`
		DependencyFailMode       string        `yaml:"security_dependency_failure_mode"`
		AllowInsecureServiceURLs bool          `yaml:"allow_insecure_service_urls"`
		ReadTimeout              time.Duration `yaml:"read_timeout"`
		WriteTimeout             time.Duration `yaml:"write_timeout"`
		IdleTimeout              time.Duration `yaml:"idle_timeout"`
		AdminAddress             string        `yaml:"admin_address"`
		UpstreamTransport        struct {
			MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`
			MaxConnsPerHost     int `yaml:"max_conns_per_host"`
		} `yaml:"upstream_transport"`
		GlobalRateLimit struct {
			RequestsPerMinute int `yaml:"requests_per_minute"`
			Burst             int `yaml:"burst"`
		} `yaml:"global_rate_limit"`
		TrustForwardedFor bool     `yaml:"trust_forwarded_for"`
		TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`
		ACME              struct {
			Enabled     bool   `yaml:"enabled"`
			AgreeTOS    bool   `yaml:"agree_tos"`
			Email       string `yaml:"email"`
			StoragePath string `yaml:"storage_path"`
			Staging     bool   `yaml:"staging"`
			DNSProvider string `yaml:"dns_provider"`
			DNSToken    string `yaml:"dns_token"`
		} `yaml:"acme"`
		IPSets struct {
			AllowList []string `yaml:"allow_list"`
			BlockList []string `yaml:"block_list"`
		} `yaml:"ip_sets"`
		Coordinator struct {
			Enabled bool   `yaml:"enabled"`
			Role    string `yaml:"role"` // leader, follower
			Address string `yaml:"address"`
			Secret  string `yaml:"secret"`
			TLS     struct {
				CAFile     string `yaml:"ca_file"`
				CertFile   string `yaml:"cert_file"`
				KeyFile    string `yaml:"key_file"`
				ServerName string `yaml:"server_name"`
			} `yaml:"tls"`
		} `yaml:"coordinator"`
	} `yaml:"global_settings"`

	Logging struct {
		AccessLog struct {
			Enabled bool   `yaml:"enabled"`
			Path    string `yaml:"path"`
			Format  string `yaml:"format"`
		} `yaml:"access_log"`
		ErrorLog struct {
			Enabled bool   `yaml:"enabled"`
			Path    string `yaml:"path"`
			Format  string `yaml:"format"`
		} `yaml:"error_log"`
		LogForwarder struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
			Token   string `yaml:"token"`
		} `yaml:"log_forwarder"`
	} `yaml:"logging"`

	CrowdSec struct {
		APIUrl string `yaml:"api_url"`
		APIKey string `yaml:"api_key"`
		// CacheTTL bounds how long a LAPI decision is reused. Unset selects
		// the default; zero disables caching and queries LAPI per request.
		CacheTTL *time.Duration `yaml:"cache_ttl"`
	} `yaml:"crowdsec"`

	GeoIP struct {
		DBPath string `yaml:"db_path"`
	} `yaml:"geoip"`

	WAFRuleSets map[string]string `yaml:"waf_rule_sets"`
	Tenants     map[string]Tenant `yaml:"tenants"`

	// builtinLLMRules records that the llm-protection rule set was not
	// supplied by the operator, so it is generated per tenant.
	builtinLLMRules bool
}

// Entry holds the WAF instance and its corresponding tenant configuration.
type Entry struct {
	WAF       coraza.WAF
	Tenant    Tenant
	BlockPage []byte
}

type wildcardDomain struct {
	domain string
	suffix string
}

// DomainManager starts certificate management for newly added tenant domains.
type DomainManager func(ctx context.Context, domains []string) error

// SafeWAFRegistry holds the mapping from FQDNs to their WAF instances and configurations.
type SafeWAFRegistry struct {
	sync.RWMutex
	reloadMu sync.Mutex
	mapping  map[string]Entry
	// wildcards indexes the "*." tenants of mapping, longest suffix first.
	// It is nil until Reload publishes a mapping; Get then scans mapping.
	wildcards     []wildcardDomain
	wafCache      map[[sha256.Size]byte]coraza.WAF
	domainManager DomainManager
	acmeEnabled   *bool
}

// NewWAFRegistry creates a new WAF registry.
func NewWAFRegistry() *SafeWAFRegistry {
	return &SafeWAFRegistry{
		mapping: make(map[string]Entry),
	}
}

// SetDomainManager registers the callback used to obtain certificates for
// tenant domains that a reload adds while ACME is enabled.
func (r *SafeWAFRegistry) SetDomainManager(manager DomainManager) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	r.domainManager = manager
}

// HasTenant reports whether host is served by a configured tenant.
func (r *SafeWAFRegistry) HasTenant(host string) bool {
	_, _, ok := r.Get(host)
	return ok
}

// GetDomains returns a list of all configured domains.
func (r *SafeWAFRegistry) GetDomains() []string {
	r.RLock()
	defer r.RUnlock()

	domains := make([]string, 0, len(r.mapping))
	for domain := range r.mapping {
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	return domains
}

// secretEnv reads a secret from NAME or, for container secret mounts, from
// the file named by NAME_FILE. NAME wins when both are set.
func secretEnv(name string) (string, error) {
	if val := os.Getenv(name); val != "" {
		return val, nil
	}
	path := os.Getenv(name + "_FILE")
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path) // #nosec G703 -- path is set by the operator through the environment
	if err != nil {
		return "", fmt.Errorf("%s_FILE: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// ApplyEnvOverrides overrides global settings from environment variables.
func (cfg *AppConfig) ApplyEnvOverrides() error {
	// Format: WAF_GLOBAL_<SETTING_NAME>
	if val := os.Getenv("WAF_GLOBAL_LOG_LEVEL"); val != "" {
		cfg.GlobalSettings.LogLevel = val
	}
	if val := os.Getenv("WAF_GLOBAL_REQUEST_BODY_LIMIT"); val != "" {
		limit, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_REQUEST_BODY_LIMIT: %w", err)
		}
		cfg.GlobalSettings.RequestBodyLimit = limit
	}
	// Deprecated alias; WAF_GLOBAL_REQUEST_BODY_LIMIT wins when both are set.
	if val := os.Getenv("WAF_GLOBAL_RESPONSE_BUFFER_LIMIT"); val != "" && os.Getenv("WAF_GLOBAL_REQUEST_BODY_LIMIT") == "" {
		limit, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_RESPONSE_BUFFER_LIMIT: %w", err)
		}
		ErrorLog.Warn("WAF_GLOBAL_RESPONSE_BUFFER_LIMIT is deprecated; use WAF_GLOBAL_REQUEST_BODY_LIMIT")
		cfg.GlobalSettings.RequestBodyLimit = limit
	}
	if val := os.Getenv("WAF_GLOBAL_RULES_DIR"); val != "" {
		cfg.GlobalSettings.RulesDir = val
	}
	if val := os.Getenv("WAF_GLOBAL_RESPONSE_MASKING_LIMIT"); val != "" {
		limit, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_RESPONSE_MASKING_LIMIT: %w", err)
		}
		cfg.GlobalSettings.ResponseMaskingLimit = limit
	}
	if val := os.Getenv("WAF_GLOBAL_REQUEST_BODY_OVERSIZE_ACTION"); val != "" {
		cfg.GlobalSettings.OversizeAction = val
	}
	if val := os.Getenv("WAF_GLOBAL_SECURITY_DEPENDENCY_FAILURE_MODE"); val != "" {
		cfg.GlobalSettings.DependencyFailMode = val
	}
	if val := os.Getenv("WAF_GLOBAL_ALLOW_INSECURE_SERVICE_URLS"); val != "" {
		allow, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_ALLOW_INSECURE_SERVICE_URLS: %w", err)
		}
		cfg.GlobalSettings.AllowInsecureServiceURLs = allow
	}
	if val := os.Getenv("WAF_GLOBAL_READ_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_READ_TIMEOUT: %w", err)
		}
		cfg.GlobalSettings.ReadTimeout = d
	}
	if val := os.Getenv("WAF_GLOBAL_WRITE_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_WRITE_TIMEOUT: %w", err)
		}
		cfg.GlobalSettings.WriteTimeout = d
	}
	if val := os.Getenv("WAF_GLOBAL_IDLE_TIMEOUT"); val != "" {
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_IDLE_TIMEOUT: %w", err)
		}
		cfg.GlobalSettings.IdleTimeout = d
	}
	if val := os.Getenv("WAF_GLOBAL_ADMIN_ADDRESS"); val != "" {
		cfg.GlobalSettings.AdminAddress = val
	}
	if val := os.Getenv("WAF_GLOBAL_ACME_ENABLED"); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_ACME_ENABLED: %w", err)
		}
		cfg.GlobalSettings.ACME.Enabled = enabled
	}
	if val := os.Getenv("WAF_GLOBAL_ACME_AGREE_TOS"); val != "" {
		agreed, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_ACME_AGREE_TOS: %w", err)
		}
		cfg.GlobalSettings.ACME.AgreeTOS = agreed
	}
	if val := os.Getenv("WAF_GLOBAL_ACME_EMAIL"); val != "" {
		cfg.GlobalSettings.ACME.Email = val
	}
	if val := os.Getenv("WAF_GLOBAL_ACME_STORAGE_PATH"); val != "" {
		cfg.GlobalSettings.ACME.StoragePath = val
	}
	if val := os.Getenv("WAF_GLOBAL_ACME_STAGING"); val != "" {
		staging, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_ACME_STAGING: %w", err)
		}
		cfg.GlobalSettings.ACME.Staging = staging
	}
	if val := os.Getenv("WAF_GLOBAL_ACME_DNS_PROVIDER"); val != "" {
		cfg.GlobalSettings.ACME.DNSProvider = val
	}
	if val, err := secretEnv("WAF_GLOBAL_ACME_DNS_TOKEN"); err != nil {
		return err
	} else if val != "" {
		cfg.GlobalSettings.ACME.DNSToken = val
	}
	if val := os.Getenv("WAF_GLOBAL_TRUST_FORWARDED_FOR"); val != "" {
		trust, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("WAF_GLOBAL_TRUST_FORWARDED_FOR: %w", err)
		}
		cfg.GlobalSettings.TrustForwardedFor = trust
	}
	if val := os.Getenv("WAF_GLOBAL_TRUSTED_PROXY_CIDRS"); val != "" {
		cfg.GlobalSettings.TrustedProxyCIDRs = strings.Split(val, ",")
		for i := range cfg.GlobalSettings.TrustedProxyCIDRs {
			cfg.GlobalSettings.TrustedProxyCIDRs[i] = strings.TrimSpace(cfg.GlobalSettings.TrustedProxyCIDRs[i])
		}
	}

	// Coordinator Overrides
	if val := os.Getenv("WAF_COORDINATOR_ENABLED"); val != "" {
		enabled, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("WAF_COORDINATOR_ENABLED: %w", err)
		}
		cfg.GlobalSettings.Coordinator.Enabled = enabled
	}
	if val := os.Getenv("WAF_COORDINATOR_ROLE"); val != "" {
		cfg.GlobalSettings.Coordinator.Role = val
	}
	if val := os.Getenv("WAF_COORDINATOR_ADDRESS"); val != "" {
		cfg.GlobalSettings.Coordinator.Address = val
	}
	if val, err := secretEnv("WAF_COORDINATOR_SECRET"); err != nil {
		return err
	} else if val != "" {
		cfg.GlobalSettings.Coordinator.Secret = val
	}
	if val := os.Getenv("WAF_COORDINATOR_TLS_CA_FILE"); val != "" {
		cfg.GlobalSettings.Coordinator.TLS.CAFile = val
	}
	if val := os.Getenv("WAF_COORDINATOR_TLS_CERT_FILE"); val != "" {
		cfg.GlobalSettings.Coordinator.TLS.CertFile = val
	}
	if val := os.Getenv("WAF_COORDINATOR_TLS_KEY_FILE"); val != "" {
		cfg.GlobalSettings.Coordinator.TLS.KeyFile = val
	}
	if val := os.Getenv("WAF_COORDINATOR_TLS_SERVER_NAME"); val != "" {
		cfg.GlobalSettings.Coordinator.TLS.ServerName = val
	}

	// CrowdSec Overrides
	if val := os.Getenv("WAF_CROWDSEC_URL"); val != "" {
		cfg.CrowdSec.APIUrl = val
	}
	if val, err := secretEnv("WAF_CROWDSEC_KEY"); err != nil {
		return err
	} else if val != "" {
		cfg.CrowdSec.APIKey = val
	}
	if val, err := secretEnv("WAF_LOG_FORWARDER_TOKEN"); err != nil {
		return err
	} else if val != "" {
		cfg.Logging.LogForwarder.Token = val
	}
	return nil
}

func decodeYAMLStrict(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not supported")
		}
		return err
	}
	return nil
}

// LoadConfig reads, layers, defaults, and validates the main config and tenant shards.
func LoadConfig(configPath string) (AppConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return AppConfig{}, fmt.Errorf("read config file: %w", err)
	}

	var cfg AppConfig
	if err := decodeYAMLStrict(data, &cfg); err != nil {
		return AppConfig{}, fmt.Errorf("decode config: %w", err)
	}

	tenantsD := filepath.Join(filepath.Dir(configPath), "tenants.d")
	files, err := os.ReadDir(tenantsD)
	if err != nil && !os.IsNotExist(err) {
		return AppConfig{}, fmt.Errorf("read tenant shard directory: %w", err)
	}
	for _, file := range files {
		if file.IsDir() || (!strings.HasSuffix(file.Name(), ".yml") && !strings.HasSuffix(file.Name(), ".yaml")) {
			continue
		}
		path := filepath.Join(tenantsD, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return AppConfig{}, fmt.Errorf("read tenant shard %s: %w", file.Name(), err)
		}
		var shard struct {
			Tenants map[string]Tenant `yaml:"tenants"`
		}
		if err := decodeYAMLStrict(data, &shard); err != nil {
			return AppConfig{}, fmt.Errorf("decode tenant shard %s: %w", file.Name(), err)
		}
		if cfg.Tenants == nil {
			cfg.Tenants = make(map[string]Tenant)
		}
		for host, tenant := range shard.Tenants {
			if _, exists := cfg.Tenants[host]; exists {
				return AppConfig{}, fmt.Errorf("tenant %s is defined more than once", host)
			}
			cfg.Tenants[host] = tenant
		}
	}

	// response_buffer_limit always limited the request body; the key was
	// renamed. The old key is folded in before environment overrides apply.
	if old := cfg.GlobalSettings.ResponseBufferLimit; old != 0 {
		if current := cfg.GlobalSettings.RequestBodyLimit; current != 0 && current != old {
			return AppConfig{}, fmt.Errorf("global_settings.response_buffer_limit is the deprecated name of request_body_limit; set only request_body_limit")
		}
		ErrorLog.Warn("global_settings.response_buffer_limit is deprecated; use request_body_limit")
		cfg.GlobalSettings.RequestBodyLimit = old
		cfg.GlobalSettings.ResponseBufferLimit = 0
	}
	if err := cfg.ApplyEnvOverrides(); err != nil {
		return AppConfig{}, fmt.Errorf("apply environment overrides: %w", err)
	}
	if cfg.WAFRuleSets == nil {
		cfg.WAFRuleSets = make(map[string]string)
	}
	if cfg.GlobalSettings.AdminAddress == "" {
		cfg.GlobalSettings.AdminAddress = "127.0.0.1:9090"
	}
	if cfg.GlobalSettings.RulesDir == "" {
		cfg.GlobalSettings.RulesDir = defaultRulesDir
	}
	if _, exists := cfg.WAFRuleSets[llmRuleSetName]; !exists {
		cfg.WAFRuleSets[llmRuleSetName] = buildLLMProtectionRules(nil)
		cfg.builtinLLMRules = true
	}
	for fqdn, tenant := range cfg.Tenants {
		tenant.Security.LLMProtection.SetDefaults()
		tenant.Security.GraphQL.SetDefaults()
		llm := &tenant.Security.LLMProtection
		usesSidecar := llm.Enabled && (llm.Mode == "ml" || llm.Mode == "hybrid")
		if usesSidecar && llm.SidecarToken != "" && llm.SidecarTokenEnv != "" {
			return AppConfig{}, fmt.Errorf("tenant %s llm_protection must set only one of sidecar_token or sidecar_token_env", fqdn)
		}
		if usesSidecar && llm.SidecarToken == "" && llm.SidecarTokenEnv != "" {
			token, err := secretEnv(llm.SidecarTokenEnv)
			if err != nil {
				return AppConfig{}, fmt.Errorf("tenant %s llm_protection token: %w", fqdn, err)
			}
			if strings.TrimSpace(token) == "" {
				return AppConfig{}, fmt.Errorf("tenant %s llm_protection token environment variable %s is empty", fqdn, llm.SidecarTokenEnv)
			}
			llm.SidecarToken = token
		}
		for i := range tenant.Security.BlockedCountries {
			tenant.Security.BlockedCountries[i] = strings.ToUpper(strings.TrimSpace(tenant.Security.BlockedCountries[i]))
		}
		cfg.Tenants[fqdn] = tenant
	}
	if err := ValidateConfig(cfg); err != nil {
		return AppConfig{}, err
	}
	// Patterns were checked by ValidateConfig, so compilation cannot fail here.
	for _, tenant := range cfg.Tenants {
		compileResponseMasking(tenant.Security.ResponseMasking)
	}
	return cfg, nil
}

// compileResponseMasking fills CompiledPattern for rules that lack it.
func compileResponseMasking(rules []ResponseMaskingRule) {
	for i := range rules {
		if rules[i].CompiledPattern == nil {
			rules[i].CompiledPattern = regexp.MustCompile(rules[i].Pattern)
		}
	}
}

func parseIPSets(cidrs []string) *[]netip.Prefix {
	if len(cidrs) == 0 {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		// Try parsing as CIDR first
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, prefix)
			continue
		}
		// Fallback to single IP
		if addr, err := netip.ParseAddr(cidr); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		ErrorLog.Errorf("invalid IP or CIDR in IP sets: %q", cidr)
	}
	return &prefixes
}

// Get retrieves the Entry for a given host and the matched domain.
func (r *SafeWAFRegistry) Get(host string) (Entry, string, bool) {
	r.RLock()
	defer r.RUnlock()

	host = normalizeHost(host)

	if entry, ok := r.mapping[host]; ok {
		return entry, host, true
	}

	// A wildcard tenant matches any depth below its suffix, so
	// "*.example.com" serves both "a.example.com" and "a.b.example.com".
	if r.wildcards != nil {
		for _, wildcard := range r.wildcards {
			if strings.HasSuffix(host, wildcard.suffix) {
				return r.mapping[wildcard.domain], wildcard.domain, true
			}
		}
		return Entry{}, "", false
	}

	var (
		bestEntry  Entry
		bestDomain string
		bestLen    int
	)

	for domain, entry := range r.mapping {
		if strings.HasPrefix(domain, "*.") {
			suffix := domain[1:]
			if strings.HasSuffix(host, suffix) && len(suffix) > bestLen {
				bestEntry = entry
				bestDomain = domain
				bestLen = len(suffix)
			}
		}
	}

	if bestDomain != "" {
		return bestEntry, bestDomain, true
	}

	return Entry{}, "", false
}

// buildWildcardIndex lists the wildcard tenants of mapping, longest suffix
// first, so the first hit is the most specific one.
func buildWildcardIndex(mapping map[string]Entry) []wildcardDomain {
	wildcards := make([]wildcardDomain, 0)
	for domain := range mapping {
		if strings.HasPrefix(domain, "*.") {
			wildcards = append(wildcards, wildcardDomain{domain: domain, suffix: domain[1:]})
		}
	}
	slices.SortFunc(wildcards, func(a, b wildcardDomain) int {
		if len(a.suffix) != len(b.suffix) {
			return len(b.suffix) - len(a.suffix)
		}
		return strings.Compare(a.domain, b.domain)
	})
	return wildcards
}

// normalizeHost lower-cases host and removes the port, the root-zone dot, and
// the brackets of an IPv6 literal.
func normalizeHost(host string) string {
	normalized := strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(normalized); err == nil {
		normalized = h
	} else if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
		normalized = normalized[1 : len(normalized)-1]
	}
	return strings.TrimSuffix(normalized, ".")
}

// rulesDirFingerprint summarizes the rule files on disk so a cached WAF is
// rebuilt when an included file changes although the directives did not.
func rulesDirFingerprint(dir string) string {
	var fingerprint strings.Builder
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		fmt.Fprintf(&fingerprint, "%s\x00%d\x00%d\n", path, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	return fingerprint.String()
}

// tenantDirectives assembles the Coraza directives of one tenant.
func tenantDirectives(cfg AppConfig, tenant Tenant) string {
	var directives strings.Builder

	// CRS 3.x reads tx.paranoia_level; CRS 4.x reads the blocking and
	// detection variants. Setting all three keeps paranoia_level effective
	// with either major version.
	level := tenant.Security.ParanoiaLevel
	fmt.Fprintf(&directives, "SecAction \"id:%d,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=%d,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"\n",
		paranoiaRuleID, level, level, level)

	for _, setName := range tenant.Security.IncludeRuleSets {
		if setName == llmRuleSetName && cfg.builtinLLMRules {
			directives.WriteString(buildLLMProtectionRules(tenant.Security.LLMProtection.InspectPaths))
		} else {
			directives.WriteString(cfg.WAFRuleSets[setName])
		}
		directives.WriteString("\n")
	}

	if tenant.Security.CustomRules != "" {
		directives.WriteString(tenant.Security.CustomRules)
		directives.WriteString("\n")
	}
	directives.WriteString(requestBodyErrorRule)
	directives.WriteString("\n")

	// Audit Mode / Detection Only (Placed after rule sets to ensure it overrides any internal SecRuleEngine directives)
	if tenant.Security.AuditMode {
		directives.WriteString("SecRuleEngine DetectionOnly\n")
	} else {
		directives.WriteString("SecRuleEngine On\n")
	}
	return directives.String()
}

// Reload parses the config file, re-initializes WAF instances, and the CrowdSec bouncer.
func (r *SafeWAFRegistry) Reload(configPath string, h *ProxyHandler) error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	success := false
	defer func() {
		if success {
			configReloadTotal.WithLabelValues("success").Inc()
		} else {
			configReloadTotal.WithLabelValues("failure").Inc()
		}
	}()

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	if r.acmeEnabled != nil && *r.acmeEnabled != cfg.GlobalSettings.ACME.Enabled {
		return fmt.Errorf("changing global_settings.acme.enabled requires a restart")
	}
	var addedDomains []string
	if cfg.GlobalSettings.ACME.Enabled {
		currentDomains := r.GetDomains()
		if len(currentDomains) > 0 {
			for domain := range cfg.Tenants {
				if normalized := normalizeHost(domain); !slices.Contains(currentDomains, normalized) {
					addedDomains = append(addedDomains, normalized)
				}
			}
			slices.Sort(addedDomains)
			if len(addedDomains) > 0 && r.domainManager == nil {
				return fmt.Errorf("tenant domain changes require a restart while ACME is enabled")
			}
		}
	}

	var nextGlobalLimiter *rate.Limiter
	if cfg.GlobalSettings.GlobalRateLimit.RequestsPerMinute > 0 {
		perSecond := rate.Limit(float64(cfg.GlobalSettings.GlobalRateLimit.RequestsPerMinute) / 60.0)
		nextGlobalLimiter = rate.NewLimiter(perSecond, cfg.GlobalSettings.GlobalRateLimit.Burst)
	}
	nextAllowIPs := parseIPSets(cfg.GlobalSettings.IPSets.AllowList)
	nextBlockIPs := parseIPSets(cfg.GlobalSettings.IPSets.BlockList)
	nextTrustedProxyCIDRs := parseIPSets(cfg.GlobalSettings.TrustedProxyCIDRs)

	h.upstreamPool.Store(&upstreamPoolSettings{
		maxIdleConnsPerHost: cfg.GlobalSettings.UpstreamTransport.MaxIdleConnsPerHost,
		maxConnsPerHost:     cfg.GlobalSettings.UpstreamTransport.MaxConnsPerHost,
	})

	newMapping := make(map[string]Entry, len(cfg.Tenants))
	newTenantStates := make(map[string]*TenantState, len(cfg.Tenants))
	tenantsPublished := false
	defer func() {
		if tenantsPublished {
			return
		}
		states := make([]*TenantState, 0, len(newTenantStates))
		for _, state := range newTenantStates {
			states = append(states, state)
		}
		closeTenantStateTransports(states)
	}()
	crowdSecRequired := false
	geoIPRequired := false

	// Tenants with identical directives share one Coraza instance, and
	// instances survive reloads that do not change their directives.
	rulesDir := cfg.GlobalSettings.RulesDir
	rulesFingerprint := rulesDirFingerprint(rulesDir)
	nextWAFCache := make(map[[sha256.Size]byte]coraza.WAF)

	for fqdn, tenant := range cfg.Tenants {
		if tenant.Security.CrowdSecEnabled != nil && *tenant.Security.CrowdSecEnabled {
			crowdSecRequired = true
		}
		if tenant.Security.GeoIPEnabled != nil && *tenant.Security.GeoIPEnabled {
			geoIPRequired = true
		}
		if tenant.Security.DevBypassSecret != "" {
			ErrorLog.Warnf("Tenant %s has dev_bypass_secret set; remove it in production", fqdn)
		}

		var waf coraza.WAF
		if tenant.Security.WAFEnabled != nil && *tenant.Security.WAFEnabled {
			directives := tenantDirectives(cfg, tenant)
			key := sha256.Sum256([]byte(rulesDir + "\x00" + rulesFingerprint + "\x00" + directives))
			cached, ok := nextWAFCache[key]
			if !ok {
				cached, ok = r.wafCache[key]
			}
			if !ok {
				conf := coraza.NewWAFConfig().
					WithDirectives(directives).
					WithRootFS(os.DirFS(rulesDir)).
					WithErrorCallback(func(rule types.MatchedRule) { h.logMatchedRule(rule) })

				cached, err = coraza.NewWAF(conf)
				if err != nil {
					return fmt.Errorf("failed to create WAF for tenant %s: %w", fqdn, err)
				}
			}
			nextWAFCache[key] = cached
			waf = cached
		}

		var blockPage []byte
		if tenant.Security.BlockPagePath != "" {
			blockPage, err = os.ReadFile(tenant.Security.BlockPagePath)
			if err != nil {
				return fmt.Errorf("tenant %s block_page_path: %w", fqdn, err)
			}
		}

		normalizedFQDN := normalizeHost(fqdn)
		state, err := h.buildTenantState(normalizedFQDN, tenant)
		if err != nil {
			return err
		}
		newTenantStates[normalizedFQDN] = state

		newMapping[normalizedFQDN] = Entry{
			WAF:       waf,
			Tenant:    tenant,
			BlockPage: blockPage,
		}
	}

	var nextBouncer *csbouncer.LiveBouncer
	nextCrowdSecHealthy := false
	if crowdSecRequired {
		nextBouncer = &csbouncer.LiveBouncer{
			APIKey: cfg.CrowdSec.APIKey,
			APIUrl: cfg.CrowdSec.APIUrl,
		}
		if err := nextBouncer.Init(); err != nil {
			return fmt.Errorf("CrowdSec bouncer init failed: %w", err)
		}
		nextBouncer.APIClient.GetClient().Timeout = securityDependencyTimeout
		probeCtx, cancel := context.WithTimeout(context.Background(), securityDependencyTimeout)
		_, probeErr := nextBouncer.Get(probeCtx, "127.0.0.1")
		cancel()
		nextCrowdSecHealthy = probeErr == nil
		if probeErr != nil && normalizeDependencyFailMode(cfg.GlobalSettings.DependencyFailMode) == dependencyFailClosed {
			return fmt.Errorf("CrowdSec readiness check failed in fail-closed mode: %w", probeErr)
		}
	}
	crowdSecCacheTTL := defaultCrowdSecCacheTTL
	if cfg.CrowdSec.CacheTTL != nil {
		crowdSecCacheTTL = *cfg.CrowdSec.CacheTTL
	}

	var nextGeoIP countryLookup
	if geoIPRequired {
		nextGeoIP, err = openCountryLookup(cfg.GeoIP.DBPath)
		if err != nil {
			return err
		}
	}

	var nextCoordinator *Coordinator
	if cfg.GlobalSettings.Coordinator.Enabled {
		candidateCoordinator := NewCoordinator(
			cfg.GlobalSettings.Coordinator.Role,
			cfg.GlobalSettings.Coordinator.Address,
			cfg.GlobalSettings.Coordinator.Secret,
		)
		if err := candidateCoordinator.ConfigureTLS(
			cfg.GlobalSettings.Coordinator.TLS.CAFile,
			cfg.GlobalSettings.Coordinator.TLS.CertFile,
			cfg.GlobalSettings.Coordinator.TLS.KeyFile,
			cfg.GlobalSettings.Coordinator.TLS.ServerName,
		); err != nil {
			if nextGeoIP != nil {
				_ = nextGeoIP.Close()
			}
			return fmt.Errorf("configure coordinator TLS: %w", err)
		}
		oldCoordinator := h.coordinator.Load()
		if oldCoordinator != nil && oldCoordinator.sameConfiguration(candidateCoordinator) {
			nextCoordinator = oldCoordinator
		} else {
			if oldCoordinator != nil && oldCoordinator.role == "leader" && candidateCoordinator.role == "leader" && oldCoordinator.address == candidateCoordinator.address {
				if nextGeoIP != nil {
					_ = nextGeoIP.Close()
				}
				return fmt.Errorf("changing coordinator leader configuration on the same address requires a restart")
			}
			if err := candidateCoordinator.Start(); err != nil {
				if nextGeoIP != nil {
					_ = nextGeoIP.Close()
				}
				return fmt.Errorf("start coordinator: %w", err)
			}
			nextCoordinator = candidateCoordinator
		}
	}

	// Probe every upstream before the new state serves traffic, so a reload
	// never publishes tenants whose health is still unknown.
	h.probeTenantStates(newTenantStates)

	limit := cfg.GlobalSettings.RequestBodyLimit
	if limit <= 0 {
		limit = defaultRequestBodyCap
	}
	h.runtimeMu.Lock()
	oldCoordinator := h.coordinator.Load()
	h.globalLimiter.Store(nextGlobalLimiter)
	h.allowIPs.Store(nextAllowIPs)
	h.blockIPs.Store(nextBlockIPs)
	h.trustedProxyCIDRs.Store(nextTrustedProxyCIDRs)
	h.coordinator.Store(nextCoordinator)
	h.trustForwardedFor.Store(cfg.GlobalSettings.TrustForwardedFor)
	h.requestBodyLimit.Store(limit)
	responseMaskingLimit := cfg.GlobalSettings.ResponseMaskingLimit
	if responseMaskingLimit <= 0 {
		responseMaskingLimit = defaultRequestBodyCap
	}
	h.responseMaskingLimit.Store(responseMaskingLimit)
	h.setDependencyFailMode(cfg.GlobalSettings.DependencyFailMode)
	h.crowdsecRequired.Store(crowdSecRequired && normalizeDependencyFailMode(cfg.GlobalSettings.DependencyFailMode) == dependencyFailClosed)
	h.crowdsecHealthy.Store(nextCrowdSecHealthy)
	h.bouncer.Store(nextBouncer)
	h.crowdsecCacheTTL.Store(int64(crowdSecCacheTTL))
	h.crowdsecCache.Purge()
	h.geoMu.Lock()
	oldGeoIP := h.geoIP
	h.geoIP = nextGeoIP
	h.geoMu.Unlock()

	healthCtx := h.restartHealthChecks()
	h.replaceTenantStates(newTenantStates)
	tenantsPublished = true
	h.llmCache.Purge()
	h.basicAuthCache.Purge()
	r.Lock()
	r.mapping = newMapping
	r.wildcards = buildWildcardIndex(newMapping)
	r.Unlock()
	r.wafCache = nextWAFCache
	acmeEnabled := cfg.GlobalSettings.ACME.Enabled
	r.acmeEnabled = &acmeEnabled
	h.startHealthChecksForStates(healthCtx, newTenantStates)
	if nextBouncer != nil {
		go h.crowdSecHealthCheck(healthCtx, nextBouncer)
	}
	if oldCoordinator != nil && oldCoordinator != nextCoordinator {
		_ = oldCoordinator.Close()
	}
	if oldGeoIP != nil && oldGeoIP != nextGeoIP {
		_ = oldGeoIP.Close()
	}
	h.runtimeMu.Unlock()

	if len(addedDomains) > 0 {
		if err := r.domainManager(context.Background(), addedDomains); err != nil {
			ErrorLog.Errorf("Failed to start certificate management for %v: %v", addedDomains, err)
		}
	}

	if nextCoordinator != nil {
		ErrorLog.Infof("Coordinator initialized as %s (Address: %s)", cfg.GlobalSettings.Coordinator.Role, cfg.GlobalSettings.Coordinator.Address)
	}

	ErrorLog.Info("Configuration reloaded successfully")
	success = true
	return nil
}
