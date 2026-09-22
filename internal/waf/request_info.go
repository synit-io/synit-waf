package waf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"path"
	"strings"
)

const requestInfoKey contextKey = "requestInfo"

var errInspectionBodyTooLarge = errors.New("request body exceeds inspection limit")

// requestInfo carries per-request state resolved once in ServeHTTP so later
// stages do not repeat tenant lookups, client IP parsing, or body reads.
type requestInfo struct {
	clientIP      string
	tenant        string // matched tenant domain, used for metrics and logs
	entry         Entry
	matched       bool
	trustedPeer   bool
	forwardedHost string
	forwardedProt string
	user          string

	bodyRead bool
	body     []byte
}

func withRequestInfo(r *http.Request, info *requestInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestInfoKey, info))
}

func requestInfoFrom(r *http.Request) *requestInfo {
	info, _ := r.Context().Value(requestInfoKey).(*requestInfo)
	return info
}

// tenantFor returns the matched tenant for r, preferring the value resolved
// by ServeHTTP and falling back to a registry lookup for direct callers.
func (h *ProxyHandler) tenantFor(r *http.Request) (Entry, string, bool) {
	if info := requestInfoFrom(r); info != nil && info.matched {
		return info.entry, info.tenant, true
	}
	return h.registry.Get(r.Host)
}

func (h *ProxyHandler) clientIPFor(r *http.Request) string {
	if info := requestInfoFrom(r); info != nil && info.clientIP != "" {
		return info.clientIP
	}
	return clientIPFromRequest(r, h.trustForwardedFor.Load(), h.trustedProxies())
}

func (h *ProxyHandler) trustedProxies() []netip.Prefix {
	if prefixes := h.trustedProxyCIDRs.Load(); prefixes != nil {
		return *prefixes
	}
	return nil
}

// inspectionBody returns the request body, reading it at most once per
// request. The body stays available to later stages and to the upstream.
func (h *ProxyHandler) inspectionBody(r *http.Request, limit int64) ([]byte, error) {
	info := requestInfoFrom(r)
	if info != nil && info.bodyRead {
		if int64(len(info.body)) > limit {
			return nil, errInspectionBodyTooLarge
		}
		return info.body, nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if r.ContentLength > limit {
		return nil, errInspectionBodyTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errInspectionBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if info != nil {
		info.body = data
		info.bodyRead = true
	}
	return data, nil
}

// pathMatchesAny reports whether urlPath falls under one of the configured
// path prefixes. The cleaned form is checked as well, so "//graphql" and
// "/x/../graphql" cannot sidestep a control bound to "/graphql".
func pathMatchesAny(prefixes []string, urlPath string) bool {
	cleaned := path.Clean("/" + urlPath)
	for _, prefix := range prefixes {
		if pathHasPrefix(urlPath, prefix) || pathHasPrefix(cleaned, prefix) {
			return true
		}
	}
	return false
}

func pathHasPrefix(urlPath, prefix string) bool {
	if !strings.HasPrefix(urlPath, prefix) {
		return false
	}
	if len(urlPath) == len(prefix) || strings.HasSuffix(prefix, "/") {
		return true
	}
	return urlPath[len(prefix)] == '/'
}

// rateLimitClientKey groups IPv6 clients by /64, the smallest block a single
// subscriber normally controls. IPv4 addresses are used as is.
func rateLimitClientKey(clientIP string) string {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return clientIP
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}
