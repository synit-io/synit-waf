package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func TestTenantDirectivesRejectUninspectableArguments(t *testing.T) {
	formAtLimit := strings.Repeat("x=1&", 999) + "x=1"
	jsonAtLimit := `{"values":[` + strings.Repeat("0,", 999) + `0]}`
	for _, tc := range []struct {
		name        string
		query       string
		body        string
		contentType string
		rules       string
		audit       bool
		blocked     bool
		matched     bool
	}{
		{name: "query at limit", query: formAtLimit},
		{name: "query over limit", query: formAtLimit + "&tail=1", blocked: true, matched: true},
		{name: "form at limit", body: formAtLimit, contentType: "application/x-www-form-urlencoded"},
		{name: "form over limit", body: formAtLimit + "&tail=1", contentType: "application/x-www-form-urlencoded", blocked: true, matched: true},
		{name: "json at limit", body: jsonAtLimit, contentType: "application/json"},
		{name: "json over limit", body: strings.TrimSuffix(jsonAtLimit, "]}") + ",0]}", contentType: "application/json", blocked: true, matched: true},
		{name: "raised operator limit", query: formAtLimit + "&tail=1", rules: "SecArgumentsLimit 2000\n"},
		{name: "audit query over limit", query: formAtLimit + "&tail=1", audit: true, matched: true},
		{name: "audit body over limit", body: formAtLimit + "&tail=1", contentType: "application/x-www-form-urlencoded", audit: true, matched: true},
		{
			name: "multipart duplicate header", contentType: "multipart/form-data; boundary=boundary",
			body: "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n" +
				"Content-Disposition: form-data; name=\"hidden\"\r\n\r\ncontent\r\n--boundary--\r\n",
			blocked: true, matched: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := Tenant{}
			tenant.Security.AuditMode = tc.audit
			tenant.Security.CustomRules = tc.rules + `
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "@streq application/json" "id:1001,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
`
			matched := false
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().
				WithDirectives(tenantDirectives(AppConfig{}, tenant)).
				WithErrorCallback(func(types.MatchedRule) { matched = true }))
			if err != nil {
				t.Fatalf("create tenant WAF: %v", err)
			}
			h := NewProxyHandler(NewWAFRegistry())
			t.Cleanup(func() { _ = h.Close() })
			method := http.MethodGet
			if tc.body != "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "http://example.com/?"+tc.query, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()
			if blocked := h.applyWAF(response, req, waf); blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v", blocked, tc.blocked)
			}
			if tc.blocked && response.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", response.Code)
			}
			if matched != tc.matched {
				t.Errorf("rule matched = %v, want %v", matched, tc.matched)
			}
		})
	}
}

func TestTenantDirectivesRejectMalformedURI(t *testing.T) {
	for _, uri := range []string{"/valid", "/bad%zz"} {
		t.Run(uri, func(t *testing.T) {
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(tenantDirectives(AppConfig{}, Tenant{})))
			if err != nil {
				t.Fatalf("create tenant WAF: %v", err)
			}
			tx := waf.NewTransaction()
			t.Cleanup(func() { _ = tx.Close() })
			tx.ProcessURI(uri, http.MethodGet, "HTTP/1.1")
			interruption := tx.ProcessRequestHeaders()
			if uri == "/valid" {
				if interruption != nil {
					t.Fatalf("valid URI rejected: %+v", interruption)
				}
			} else if interruption == nil || interruption.Status != http.StatusForbidden {
				t.Fatalf("malformed URI interruption = %+v, want 403", interruption)
			}
		})
	}
}
