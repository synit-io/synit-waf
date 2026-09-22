package waf

import (
	"math"
	"testing"
	"time"
)

func baseValidConfig() AppConfig {
	cfg := AppConfig{}
	cfg.GlobalSettings.OversizeAction = oversizeActionReject
	cfg.CrowdSec.APIUrl = "http://localhost:8080"
	cfg.CrowdSec.APIKey = "secret"
	cfg.Tenants = make(map[string]Tenant)
	cfg.Tenants["api.example.com"] = Tenant{
		Upstreams: []Upstream{{URL: "http://localhost:8080"}},
		Security: SecurityPolicy{
			WAFEnabled:      new(true),
			ParanoiaLevel:   1,
			IncludeRuleSets: []string{"base"},
		},
	}
	cfg.WAFRuleSets = map[string]string{"base": "SecRuleEngine On"}
	return cfg
}

func TestValidateConfigOK(t *testing.T) {
	cfg := baseValidConfig()
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("expected config to be valid, got: %v", err)
	}
}

func TestValidateConfigRejectsUnknownRuleSet(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Tenants["api.example.com"] = Tenant{
		Upstreams: []Upstream{{URL: "http://localhost:8080"}},
		Security: SecurityPolicy{
			WAFEnabled:      new(true),
			ParanoiaLevel:   1,
			IncludeRuleSets: []string{"unknown"},
		},
	}

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected config to be rejected due to unknown rule set")
	}
}

func TestValidateConfigRejectsInvalidOversizeAction(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GlobalSettings.OversizeAction = "invalid"

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected config to be rejected due to invalid oversize action")
	}
}

func TestValidateConfigRejectsInvalidDependencyMode(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GlobalSettings.DependencyFailMode = "invalid"

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected config to be rejected due to invalid dependency mode")
	}
}

func TestValidateConfigRejectsNonFiniteLLMThreshold(t *testing.T) {
	cfg := baseValidConfig()
	tenant := cfg.Tenants["api.example.com"]
	tenant.Security.LLMProtection = LLMProtectionConfig{
		Enabled:      true,
		Mode:         "ml",
		Action:       "deny",
		FailMode:     "closed",
		Threshold:    math.NaN(),
		Timeout:      time.Second,
		MaxTextBytes: 1024,
		SidecarURL:   "http://localhost:5001/v1/detect",
		SidecarToken: "secret",
	}
	cfg.Tenants["api.example.com"] = tenant

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected non-finite LLM threshold to be rejected")
	}
}

func TestValidateConfigRejectsInvalidGlobalRateLimit(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GlobalSettings.GlobalRateLimit.RequestsPerMinute = 100
	cfg.GlobalSettings.GlobalRateLimit.Burst = 0 // Invalid: burst must be > 0 when RPM > 0

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected global rate limit burst validation error")
	}

	cfg.GlobalSettings.GlobalRateLimit.RequestsPerMinute = -1
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected global rate limit negative RPM validation error")
	}
}

func TestValidateConfigRejectsInvalidIPSet(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GlobalSettings.IPSets.BlockList = []string{"not-an-ip"}

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected invalid IP set entry to be rejected")
	}
}

func TestValidateConfigRejectsRulesOnlyLLMWithoutWAF(t *testing.T) {
	cfg := baseValidConfig()
	tenant := cfg.Tenants["api.example.com"]
	tenant.Security.WAFEnabled = new(false)
	tenant.Security.LLMProtection = LLMProtectionConfig{
		Enabled:      true,
		Mode:         "rules",
		Action:       "deny",
		FailMode:     "closed",
		Threshold:    0.85,
		Timeout:      time.Second,
		MaxTextBytes: 1024,
	}
	cfg.Tenants["api.example.com"] = tenant

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected rules-only LLM protection without WAF to be rejected")
	}
}

func TestValidateConfigRejectsMLWithoutSidecarToken(t *testing.T) {
	cfg := baseValidConfig()
	tenant := cfg.Tenants["api.example.com"]
	tenant.Security.LLMProtection = LLMProtectionConfig{
		Enabled:      true,
		Mode:         "ml",
		Action:       "deny",
		FailMode:     "closed",
		Threshold:    0.85,
		Timeout:      time.Second,
		MaxTextBytes: 1024,
		SidecarURL:   "http://localhost:5001/v1/detect",
	}
	cfg.Tenants["api.example.com"] = tenant

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected ML protection without sidecar token to be rejected")
	}
}

func TestValidateConfigRejectsCoordinatorWithoutSecret(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GlobalSettings.Coordinator.Enabled = true
	cfg.GlobalSettings.Coordinator.Role = "leader"
	cfg.GlobalSettings.Coordinator.Address = "127.0.0.1:9000"

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected coordinator without secret to be rejected")
	}
}

func TestValidateConfigRejectsInsecureExternalSecurityURL(t *testing.T) {
	cfg := baseValidConfig()
	tenant := cfg.Tenants["api.example.com"]
	tenant.Security.JWTValidation.Enabled = true
	tenant.Security.JWTValidation.JWKSEndpoint = "http://keys.example.com/jwks"
	tenant.Security.JWTValidation.Issuer = "issuer"
	tenant.Security.JWTValidation.Audience = "audience"
	cfg.Tenants["api.example.com"] = tenant

	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected insecure external JWKS URL to be rejected")
	}
}

func TestValidateConfigHasNoSideEffects(t *testing.T) {
	cfg := baseValidConfig()
	tenant := cfg.Tenants["api.example.com"]
	tenant.Security.ResponseMasking = []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}}
	cfg.Tenants["api.example.com"] = tenant

	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if cfg.Tenants["api.example.com"].Security.ResponseMasking[0].CompiledPattern != nil {
		t.Fatal("expected validation to leave the configuration unchanged")
	}
}

func TestBuildTenantStateCompilesResponseMaskingPatterns(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	t.Cleanup(func() { _ = h.Close() })
	tenant := Tenant{Upstreams: []Upstream{{URL: "http://127.0.0.1:1"}}}
	tenant.Security.ResponseMasking = []ResponseMaskingRule{{Pattern: "(", Replacement: "masked"}}
	if _, err := h.buildTenantState("api.example.com", tenant); err == nil {
		t.Fatal("expected invalid masking pattern to be rejected before serving traffic")
	}
}

func TestValidateConfigRejectsUnsafeReleaseSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AppConfig)
	}{
		{name: "upstream userinfo", mutate: func(cfg *AppConfig) {
			tenant := cfg.Tenants["api.example.com"]
			tenant.Upstreams[0].URL = "http://user:secret@localhost:8080"
			cfg.Tenants["api.example.com"] = tenant
		}},
		{name: "invalid circuit threshold", mutate: func(cfg *AppConfig) {
			tenant := cfg.Tenants["api.example.com"]
			tenant.Security.CircuitBreaker.Enabled = true
			tenant.Security.CircuitBreaker.Threshold = 0
			cfg.Tenants["api.example.com"] = tenant
		}},
		{name: "masking representation transform", mutate: func(cfg *AppConfig) {
			tenant := cfg.Tenants["api.example.com"]
			tenant.Security.ResponseMasking = []ResponseMaskingRule{{Pattern: "secret", Replacement: "masked"}}
			tenant.HeaderTransform.StripResponse = []string{"Content-Encoding"}
			cfg.Tenants["api.example.com"] = tenant
		}},
		{name: "invalid file log format", mutate: func(cfg *AppConfig) {
			cfg.Logging.AccessLog.Enabled = true
			cfg.Logging.AccessLog.Path = "/tmp/access.log"
			cfg.Logging.AccessLog.Format = "xml"
		}},
		{name: "cloudflare without token", mutate: func(cfg *AppConfig) {
			cfg.GlobalSettings.ACME.Enabled = true
			cfg.GlobalSettings.ACME.Email = "ops@example.com"
			cfg.GlobalSettings.ACME.DNSProvider = "cloudflare"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseValidConfig()
			tt.mutate(&cfg)
			if err := ValidateConfig(cfg); err == nil {
				t.Fatal("expected config to be rejected")
			}
		})
	}
}
