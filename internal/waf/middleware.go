package waf

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/golang-jwt/jwt/v5"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// UpstreamServer represents a single upstream server.
type UpstreamServer struct {
	Tenant              string
	URL                 *url.URL
	Proxy               *httputil.ReverseProxy
	Transport           *http.Transport
	isHealthy           atomic.Bool
	consecutiveFailures atomic.Int32
	deadUntil           atomic.Int64 // Unix timestamp
	healthCheck         HealthCheckConfig
	healthClient        *http.Client
}

type upstreamPoolSettings struct {
	maxIdleConnsPerHost int
	maxConnsPerHost     int
}

// crowdsecDecision is a cached LAPI verdict for one client IP.
type crowdsecDecision struct {
	banned  bool
	expires time.Time
}

// wafTransactionMeta links a running Coraza transaction to its tenant, so the
// shared error callback can attribute matched rules.
type wafTransactionMeta struct {
	tenant string
	host   string
	audit  bool
}

// TenantState holds the state for a tenant, including its upstreams and a counter for round-robin load balancing.
type TenantState struct {
	upstreams []*UpstreamServer
	counter   atomic.Uint64
}

type rateLimiterState struct {
	requestsPerMinute int
	burst             int
	limiter           *rate.Limiter
}

// loggingResponseWriter is a wrapper to capture status code and size for access logs.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	size        int64
	wroteHeader bool
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	// Informational responses do not end the header phase.
	if code >= 200 || code == http.StatusSwitchingProtocols {
		w.wroteHeader = true
		w.statusCode = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingResponseWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	n, err := w.ResponseWriter.Write(b)
	w.size += int64(n)
	return n, err
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ProxyHandler holds the registry, the shared reverse proxy, and the CrowdSec bouncer.
type ProxyHandler struct {
	runtimeMu            sync.RWMutex
	registry             *SafeWAFRegistry
	bouncer              atomic.Pointer[csbouncer.LiveBouncer]
	crowdsecHealthy      atomic.Bool
	crowdsecCache        *lru.Cache[string, crowdsecDecision]
	crowdsecCacheTTL     atomic.Int64 // time.Duration; zero disables the cache
	tenantStates         sync.Map
	requestBodyLimit     atomic.Int64
	responseMaskingLimit atomic.Int64
	crowdsecRequired     atomic.Bool
	dependencyMode       atomic.Value
	rateLimiters         *expirable.LRU[string, *rateLimiterState]
	rateLimiterMu        sync.Mutex
	llmCache             *expirable.LRU[string, float64]
	globalLimiter        atomic.Pointer[rate.Limiter]
	jwksCache            sync.Map // map[string]*jwksCacheEntry
	jwksCacheMu          sync.Mutex
	jwksLocksMu          sync.Mutex
	jwksLocks            map[string]*jwksRefreshLock
	jwksClient           *http.Client
	coordinator          atomic.Pointer[Coordinator]
	allowIPs             atomic.Pointer[[]netip.Prefix]
	blockIPs             atomic.Pointer[[]netip.Prefix]
	trustForwardedFor    atomic.Bool
	trustedProxyCIDRs    atomic.Pointer[[]netip.Prefix]
	upstreamPool         atomic.Pointer[upstreamPoolSettings]
	basicAuthCache       *expirable.LRU[[sha256.Size]byte, struct{}]
	basicAuthKey         []byte
	sidecarClient        *http.Client
	activeTx             sync.Map // map[string]wafTransactionMeta keyed by Coraza transaction ID
	unknownHostLog       rate.Sometimes
	coordinatorLog       rate.Sometimes

	// geoMu guards geoIP. Lookups hold the read lock only for the in-memory
	// database access, so a reload can close the previous reader safely.
	geoMu sync.RWMutex
	geoIP countryLookup

	healthChecksMu   sync.Mutex
	healthChecksStop context.CancelFunc
}

type jwksCacheEntry struct {
	keys              map[string]any
	expiresAt         time.Time
	lastForcedRefresh time.Time
}

type jwksRefreshLock struct {
	mu   sync.Mutex
	refs int
}

var (
	errResponseInspection         = errors.New("response masking inspection failed")
	errResponseInspectionOversize = fmt.Errorf("%w: response exceeds masking inspection limit", errResponseInspection)
)

const (
	maxJWKSResponseBytes      = 1 << 20
	maxJWKSKeys               = 100
	maxJWKSCacheEntries       = 256
	maxJWKSCacheTTL           = time.Hour
	minJWKSForcedRefreshDelay = 30 * time.Second
	securityDependencyTimeout = 2 * time.Second
)

func decodeBase64UrlUint(s string) (*big.Int, error) {
	b, err := decodeBase64URL(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func decodeBase64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return base64.URLEncoding.DecodeString(s)
	}
	return b, nil
}

func parseJWK(jwkMap map[string]any) (any, error) {
	kty, _ := jwkMap["kty"].(string)
	switch kty {
	case "RSA":
		nStr, _ := jwkMap["n"].(string)
		eStr, _ := jwkMap["e"].(string)
		if nStr == "" || eStr == "" {
			return nil, fmt.Errorf("missing n or e in RSA JWK")
		}
		n, err := decodeBase64UrlUint(nStr)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			eBytes, err = base64.URLEncoding.DecodeString(eStr)
			if err != nil {
				return nil, err
			}
		}
		var e int
		for _, b := range eBytes {
			e = (e << 8) | int(b)
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		crv, _ := jwkMap["crv"].(string)
		xStr, _ := jwkMap["x"].(string)
		yStr, _ := jwkMap["y"].(string)
		if crv == "" || xStr == "" || yStr == "" {
			return nil, fmt.Errorf("missing crv, x, or y in EC JWK")
		}
		var curve elliptic.Curve
		var coordinateSize int
		switch crv {
		case "P-256":
			curve = elliptic.P256()
			coordinateSize = 32
		case "P-384":
			curve = elliptic.P384()
			coordinateSize = 48
		case "P-521":
			curve = elliptic.P521()
			coordinateSize = 66
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", crv)
		}
		x, err := decodeBase64URL(xStr)
		if err != nil {
			return nil, err
		}
		y, err := decodeBase64URL(yStr)
		if err != nil {
			return nil, err
		}
		if len(x) > coordinateSize || len(y) > coordinateSize {
			return nil, fmt.Errorf("invalid EC coordinate size")
		}
		publicKey := make([]byte, 1+2*coordinateSize)
		publicKey[0] = 4
		copy(publicKey[1+coordinateSize-len(x):1+coordinateSize], x)
		copy(publicKey[1+2*coordinateSize-len(y):], y)
		key, err := ecdsa.ParseUncompressedPublicKey(curve, publicKey)
		if err != nil {
			return nil, fmt.Errorf("parse EC public key: %w", err)
		}
		return key, nil
	case "OKP":
		crv, _ := jwkMap["crv"].(string)
		xStr, _ := jwkMap["x"].(string)
		if crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
		}
		x, err := decodeBase64URL(xStr)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// jwtValidMethods lists the accepted asymmetric algorithms. HMAC and "none"
// are excluded because the verification keys come from a public JWKS.
var jwtValidMethods = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// jwtKeyMatchesMethod rejects a key whose type does not belong to the
// algorithm family named in the token header.
func jwtKeyMatchesMethod(method jwt.SigningMethod, key any) bool {
	switch method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		_, ok := key.(*rsa.PublicKey)
		return ok
	case *jwt.SigningMethodECDSA:
		_, ok := key.(*ecdsa.PublicKey)
		return ok
	case *jwt.SigningMethodEd25519:
		_, ok := key.(ed25519.PublicKey)
		return ok
	default:
		return false
	}
}

func (h *ProxyHandler) validateJWT(w http.ResponseWriter, r *http.Request, cfg JWTValidationConfig) bool {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
		return false
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// 1. Get or Refresh JWKS
	entry, err := h.getJWKSEntry(r.Context(), cfg.JWKSEndpoint, nil)
	if err != nil {
		ErrorLog.Errorf("failed to get JWKS from %s: %v", cfg.JWKSEndpoint, err)
		http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
		return false
	}

	// 2. Parse and Validate Token
	var refreshErr error
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Kid check
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header missing from token")
		}

		key, ok := entry.keys[kid]
		if !ok {
			refreshed, err := h.getJWKSEntry(r.Context(), cfg.JWKSEndpoint, entry)
			if err != nil {
				refreshErr = err
				return nil, fmt.Errorf("refresh JWKS for key %q: %w", kid, err)
			}
			entry = refreshed
			key, ok = entry.keys[kid]
			if !ok {
				return nil, fmt.Errorf("key %q not found in JWKS", kid)
			}
		}
		if !jwtKeyMatchesMethod(token.Method, key) {
			return nil, fmt.Errorf("key %q does not match signing method %v", kid, token.Header["alg"])
		}
		return key, nil
	}, jwt.WithValidMethods(jwtValidMethods), jwt.WithIssuer(cfg.Issuer), jwt.WithAudience(cfg.Audience), jwt.WithExpirationRequired())

	if refreshErr != nil {
		ErrorLog.Errorf("failed to refresh JWKS from %s: %v", cfg.JWKSEndpoint, refreshErr)
		http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
		return false
	}
	if err != nil {
		ErrorLog.Infof("JWT validation failed for %s: %v", r.Host, err)
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return false
	}

	if !token.Valid {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return false
	}

	return true
}

func (h *ProxyHandler) getJWKS(ctx context.Context, endpoint string) (map[string]any, error) {
	entry, err := h.getJWKSEntry(ctx, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return entry.keys, nil
}

func (h *ProxyHandler) getJWKSEntry(ctx context.Context, endpoint string, previous *jwksCacheEntry) (*jwksCacheEntry, error) {
	now := time.Now()
	if entry := h.loadJWKSCacheEntry(endpoint); entry != nil {
		switch {
		case previous == nil && now.Before(entry.expiresAt):
			return entry, nil
		case previous != nil && entry != previous && now.Before(entry.expiresAt):
			return entry, nil
		}
	}

	refreshLock := h.acquireJWKSRefreshLock(endpoint)
	defer h.releaseJWKSRefreshLock(endpoint, refreshLock)
	refreshLock.mu.Lock()
	defer refreshLock.mu.Unlock()

	now = time.Now()
	if entry := h.loadJWKSCacheEntry(endpoint); entry != nil {
		switch {
		case previous == nil && now.Before(entry.expiresAt):
			return entry, nil
		case previous != nil && entry != previous && now.Before(entry.expiresAt):
			return entry, nil
		case previous != nil && now.Sub(entry.lastForcedRefresh) < minJWKSForcedRefreshDelay:
			return entry, nil
		}
	}

	// Fetch new keys
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.jwksClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxJWKSResponseBytes {
		return nil, fmt.Errorf("JWKS response exceeds %d bytes", maxJWKSResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}
	if len(body) > maxJWKSResponseBytes {
		return nil, fmt.Errorf("JWKS response exceeds %d bytes", maxJWKSResponseBytes)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("JWKS response contains %d keys; maximum is %d", len(jwks.Keys), maxJWKSKeys)
	}

	parsedKeys := make(map[string]any)
	for _, k := range jwks.Keys {
		kid, _ := k["kid"].(string)
		if kid == "" {
			continue // skip keys without kid
		}
		if _, exists := parsedKeys[kid]; exists {
			return nil, fmt.Errorf("JWKS contains duplicate kid %q", kid)
		}
		parsed, err := parseJWK(k)
		if err != nil {
			ErrorLog.Warnf("failed to parse JWK key %s: %v", kid, err)
			continue
		}
		parsedKeys[kid] = parsed
	}

	if len(parsedKeys) == 0 {
		return nil, fmt.Errorf("no valid keys found in JWKS")
	}

	ttl := 15 * time.Minute
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		for part := range strings.SplitSeq(cc, ",") {
			part = strings.TrimSpace(part)
			if after, ok := strings.CutPrefix(part, "max-age="); ok {
				if ma, err := strconv.Atoi(after); err == nil && ma > 0 {
					ttl = time.Duration(ma) * time.Second
				}
			}
		}
	}
	if ttl > maxJWKSCacheTTL {
		ttl = maxJWKSCacheTTL
	}

	entry := &jwksCacheEntry{
		keys:      parsedKeys,
		expiresAt: now.Add(ttl),
	}
	if previous != nil {
		entry.lastForcedRefresh = now
	}
	h.storeJWKSCacheEntry(endpoint, entry)

	return entry, nil
}

func (h *ProxyHandler) loadJWKSCacheEntry(endpoint string) *jwksCacheEntry {
	value, ok := h.jwksCache.Load(endpoint)
	if !ok {
		return nil
	}
	return value.(*jwksCacheEntry)
}

func (h *ProxyHandler) acquireJWKSRefreshLock(endpoint string) *jwksRefreshLock {
	h.jwksLocksMu.Lock()
	defer h.jwksLocksMu.Unlock()
	if h.jwksLocks == nil {
		h.jwksLocks = make(map[string]*jwksRefreshLock)
	}
	lock := h.jwksLocks[endpoint]
	if lock == nil {
		lock = &jwksRefreshLock{}
		h.jwksLocks[endpoint] = lock
	}
	lock.refs++
	return lock
}

func (h *ProxyHandler) releaseJWKSRefreshLock(endpoint string, lock *jwksRefreshLock) {
	h.jwksLocksMu.Lock()
	defer h.jwksLocksMu.Unlock()
	lock.refs--
	if lock.refs == 0 {
		delete(h.jwksLocks, endpoint)
	}
}

func (h *ProxyHandler) storeJWKSCacheEntry(endpoint string, entry *jwksCacheEntry) {
	h.jwksCacheMu.Lock()
	defer h.jwksCacheMu.Unlock()
	h.jwksCache.Store(endpoint, entry)

	now := time.Now()
	count := 0
	oldestEndpoint := ""
	var oldestExpiry time.Time
	h.jwksCache.Range(func(key, value any) bool {
		cachedEndpoint := key.(string)
		cached := value.(*jwksCacheEntry)
		if cachedEndpoint != endpoint && !now.Before(cached.expiresAt) {
			h.jwksCache.Delete(cachedEndpoint)
			return true
		}
		count++
		if cachedEndpoint != endpoint && (oldestEndpoint == "" || cached.expiresAt.Before(oldestExpiry)) {
			oldestEndpoint = cachedEndpoint
			oldestExpiry = cached.expiresAt
		}
		return true
	})
	if count > maxJWKSCacheEntries && oldestEndpoint != "" {
		h.jwksCache.Delete(oldestEndpoint)
	}
}

// NewProxyHandler creates a new proxy handler.
func NewProxyHandler(registry *SafeWAFRegistry) *ProxyHandler {
	h := &ProxyHandler{
		registry:   registry,
		jwksClient: &http.Client{Timeout: 5 * time.Second},
		// The sidecar budget is tens of milliseconds, so requests must reuse
		// warm connections instead of the two idle ones of DefaultTransport.
		sidecarClient: &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
		}},
		unknownHostLog: rate.Sometimes{Interval: time.Second},
		coordinatorLog: rate.Sometimes{Interval: 5 * time.Second},
	}
	h.requestBodyLimit.Store(defaultRequestBodyCap)
	h.responseMaskingLimit.Store(defaultRequestBodyCap)
	h.dependencyMode.Store(dependencyFailOpen)
	h.crowdsecCacheTTL.Store(int64(defaultCrowdSecCacheTTL))
	h.crowdsecCache, _ = lru.New[string, crowdsecDecision](50000)
	// Successful basic-auth checks are remembered briefly so bcrypt does not
	// run on every request. Keys are HMACs under a per-process random key.
	h.basicAuthCache = expirable.NewLRU[[sha256.Size]byte, struct{}](4096, nil, 5*time.Minute)
	h.basicAuthKey = make([]byte, 32)
	if _, err := rand.Read(h.basicAuthKey); err != nil {
		panic(fmt.Sprintf("read random basic-auth cache key: %v", err))
	}
	// Bounded LRU cache for 10,000 unique client+tenant combinations with 10m TTL
	h.rateLimiters = expirable.NewLRU[string, *rateLimiterState](10000, nil, 10*time.Minute)
	// Bounded LRU cache for 10,000 unique prompt verdicts with 10m TTL
	h.llmCache = expirable.NewLRU[string, float64](10000, nil, 10*time.Minute)
	return h
}

// Close stops background health checks and coordinator resources.
func (h *ProxyHandler) Close() error {
	h.runtimeMu.Lock()
	defer h.runtimeMu.Unlock()
	h.healthChecksMu.Lock()
	if h.healthChecksStop != nil {
		h.healthChecksStop()
		h.healthChecksStop = nil
	}
	h.healthChecksMu.Unlock()
	var errs []error
	if coordinator := h.coordinator.Swap(nil); coordinator != nil {
		errs = append(errs, coordinator.Close())
	}
	h.geoMu.Lock()
	if h.geoIP != nil {
		errs = append(errs, h.geoIP.Close())
		h.geoIP = nil
	}
	h.geoMu.Unlock()
	if transport, ok := h.sidecarClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	var states []*TenantState
	h.tenantStates.Range(func(_, value any) bool {
		states = append(states, value.(*TenantState))
		return true
	})
	closeTenantStates(states, nil)
	return errors.Join(errs...)
}

func (h *ProxyHandler) recordUpstreamFailure(u *UpstreamServer, threshold int, cooldown time.Duration) {
	fails := u.consecutiveFailures.Add(1)
	if int(fails) >= threshold {
		if cooldown == 0 {
			cooldown = 30 * time.Second
		}
		u.deadUntil.Store(time.Now().Add(cooldown).Unix())
		ErrorLog.Warnf("Upstream %s marked as dead for %v due to %d consecutive failures", u.URL.Redacted(), cooldown, fails)
	}
}

// isMaskableMediaType reports whether a response of this type is inspected.
func isMaskableMediaType(mediaType string) bool {
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") ||
		mediaType == "application/xml" || strings.HasSuffix(mediaType, "+xml")
}

func (h *ProxyHandler) applyResponseMasking(resp *http.Response, rules []ResponseMaskingRule) error {
	if resp.Body == nil || resp.ContentLength == 0 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200) || (resp.Request != nil && resp.Request.Method == http.MethodHead) {
		return nil
	}
	if resp.StatusCode == http.StatusPartialContent {
		return fmt.Errorf("%w: partial responses are not supported", errResponseInspection)
	}
	// A response without a usable Content-Type is buffered and sniffed, so an
	// upstream cannot skip masking by omitting the header.
	sniff := false
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		sniff = true
	} else {
		mediaType = strings.ToLower(mediaType)
		if !isMaskableMediaType(mediaType) {
			return nil
		}
		if mediaType == "text/event-stream" {
			return fmt.Errorf("%w: event streams are not supported", errResponseInspection)
		}
	}
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return fmt.Errorf("%w: Content-Encoding %q is not supported", errResponseInspection, encoding)
	}
	limit := h.responseMaskingLimit.Load()
	if limit <= 0 {
		limit = defaultRequestBodyCap
	}
	if resp.ContentLength > limit {
		_ = resp.Body.Close()
		return errResponseInspectionOversize
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		_ = resp.Body.Close()
		return fmt.Errorf("read response body for masking: %w", err)
	}
	_ = resp.Body.Close()
	if int64(len(body)) > limit {
		return errResponseInspectionOversize
	}
	if sniff {
		sniffed, _, _ := mime.ParseMediaType(http.DetectContentType(body))
		if !isMaskableMediaType(sniffed) {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return nil
		}
	}

	masked := body
	for _, rule := range rules {
		pattern := rule.CompiledPattern
		if pattern == nil {
			// Rules loaded through LoadConfig or buildTenantState are
			// precompiled; this path serves direct callers only.
			pattern, err = regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("compile masking pattern %q: %w", rule.Pattern, err)
			}
		}
		if pattern.Match(masked) {
			masked = pattern.ReplaceAll(masked, []byte(rule.Replacement))
		}
	}

	if !bytes.Equal(masked, body) {
		resp.ContentLength = int64(len(masked))
		resp.Header.Set("Content-Length", strconv.Itoa(len(masked)))
		resp.Header.Set("X-Synit-Masked", "true")
	}
	resp.Body = io.NopCloser(bytes.NewReader(masked))
	return nil
}

// selectUpstream selects a healthy upstream using a round-robin strategy.
func (ts *TenantState) selectUpstream() *UpstreamServer {
	upstreams := ts.upstreams
	numUpstreams := len(upstreams)
	if numUpstreams == 0 {
		return nil
	}

	now := time.Now().Unix()
	for range numUpstreams {
		counter := ts.counter.Add(1)
		idx := int(counter % uint64(numUpstreams))
		upstream := upstreams[idx]

		// Passive Health Check (Circuit Breaker)
		if deadUntil := upstream.deadUntil.Load(); deadUntil > 0 {
			if now < deadUntil {
				continue // Still in cooldown
			}
			// Cooldown expired, try again
			upstream.deadUntil.Store(0)
		}

		if upstream.isHealthy.Load() {
			return upstream
		}
	}
	return nil
}

func (h *ProxyHandler) restartHealthChecks() context.Context {
	h.healthChecksMu.Lock()
	defer h.healthChecksMu.Unlock()

	if h.healthChecksStop != nil {
		h.healthChecksStop()
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.healthChecksStop = cancel
	return ctx
}

func (h *ProxyHandler) buildTenantState(fqdn string, tenant Tenant) (*TenantState, error) {
	// Work on a private copy so compiled patterns do not leak into the caller's config.
	tenant.Security.ResponseMasking = slices.Clone(tenant.Security.ResponseMasking)
	for i := range tenant.Security.ResponseMasking {
		rule := &tenant.Security.ResponseMasking[i]
		if rule.CompiledPattern == nil {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("tenant %s has invalid response_masking pattern %q: %w", fqdn, rule.Pattern, err)
			}
			rule.CompiledPattern = compiled
		}
	}

	pool := upstreamPoolSettings{}
	if configured := h.upstreamPool.Load(); configured != nil {
		pool = *configured
	}
	if pool.maxIdleConnsPerHost <= 0 {
		pool.maxIdleConnsPerHost = defaultUpstreamMaxIdleConnsPerHost
	}
	healthCheck := tenant.HealthCheck
	if healthCheck.Interval <= 0 {
		healthCheck.Interval = defaultHealthCheckInterval
	}
	if healthCheck.Timeout <= 0 {
		healthCheck.Timeout = defaultHealthCheckTimeout
	}

	upstreams := make([]*UpstreamServer, 0, len(tenant.Upstreams))
	for _, upstreamConfig := range tenant.Upstreams {
		target, err := url.Parse(upstreamConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("tenant %s has invalid upstream URL %q: %w", fqdn, upstreamConfig.URL, err)
		}

		responseHeaderTimeout := upstreamConfig.ResponseHeaderTimeout
		if responseHeaderTimeout == 0 {
			responseHeaderTimeout = 30 * time.Second
		}
		// Each transport serves one upstream host, so the per-host idle pool
		// is the effective pool. The net/http default of 2 forces a new
		// connection for almost every request under load.
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          pool.maxIdleConnsPerHost,
			MaxIdleConnsPerHost:   pool.maxIdleConnsPerHost,
			MaxConnsPerHost:       pool.maxConnsPerHost,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		}

		if tenant.UpstreamInsecure != nil && *tenant.UpstreamInsecure {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}

		upstream := &UpstreamServer{
			Tenant:      fqdn,
			URL:         target,
			Transport:   transport,
			healthCheck: healthCheck,
			healthClient: &http.Client{
				Transport: transport,
				Timeout:   healthCheck.Timeout,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		}
		upstream.isHealthy.Store(true)

		proxy := &httputil.ReverseProxy{Transport: transport}
		// Rewrite runs after net/http removed hop-by-hop headers and the
		// client's Forwarded and X-Forwarded-* headers from the outbound
		// request. Headers set here cannot be stripped through "Connection",
		// and forwarding headers cannot be spoofed by the client.
		proxy.Rewrite = func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host

			clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr)
			if err != nil {
				clientIP = pr.In.RemoteAddr
			}
			forwardedHost := pr.In.Host
			forwardedProto := "http"
			if pr.In.TLS != nil {
				forwardedProto = "https"
			}
			if info := requestInfoFrom(pr.In); info != nil {
				if info.clientIP != "" {
					clientIP = info.clientIP
				}
				// Only a trusted proxy may describe the original request.
				if info.trustedPeer {
					if info.forwardedHost != "" {
						forwardedHost = info.forwardedHost
					}
					if info.forwardedProt != "" {
						forwardedProto = info.forwardedProt
					}
				}
			}
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
			pr.Out.Header.Set("X-Forwarded-Host", forwardedHost)
			pr.Out.Header.Set("X-Forwarded-Proto", forwardedProto)
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.Out.Header.Del(devBypassHeader)

			// 6. Header Transformation (Request)
			for _, key := range tenant.HeaderTransform.StripRequest {
				pr.Out.Header.Del(key)
			}
			for key, value := range tenant.HeaderTransform.InjectRequest {
				value = strings.ReplaceAll(value, "{{TENANT}}", fqdn)
				value = strings.ReplaceAll(value, "{{CLIENT_IP}}", clientIP)
				pr.Out.Header.Set(key, value)
			}
			if len(tenant.Security.ResponseMasking) > 0 {
				pr.Out.Header.Del("Accept-Encoding")
				pr.Out.Header.Del("Range")
				pr.Out.Header.Del("If-Range")
			}
		}
		upstream.Proxy = proxy
		upstreamLabel := target.Redacted()

		// 7. Header Transformation (Response) & Circuit Breaker & Response Masking
		proxy.ModifyResponse = func(resp *http.Response) error {
			upstreamRequestsTotal.WithLabelValues(fqdn, upstreamLabel, statusClassLabel(resp.StatusCode)).Inc()
			// Circuit Breaker (Failure Status Codes)
			if tenant.Security.CircuitBreaker.Enabled {
				isFailure := slices.Contains(tenant.Security.CircuitBreaker.FailureStatusCodes, resp.StatusCode)
				if isFailure {
					h.recordUpstreamFailure(upstream, tenant.Security.CircuitBreaker.Threshold, tenant.Security.CircuitBreaker.Cooldown)
				} else {
					upstream.consecutiveFailures.Store(0)
				}
			} else {
				upstream.consecutiveFailures.Store(0)
			}

			// 8. Response Data Masking
			if len(tenant.Security.ResponseMasking) > 0 {
				if err := h.applyResponseMasking(resp, tenant.Security.ResponseMasking); err != nil {
					return err
				}
			}

			// Transform only after inspecting the original upstream representation.
			for _, key := range tenant.HeaderTransform.StripResponse {
				resp.Header.Del(key)
			}
			for key, value := range tenant.HeaderTransform.InjectResponse {
				resp.Header.Set(key, value)
			}

			return nil
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			ErrorLog.Errorf("Proxy error for %s: %v", fqdn, err)
			upstreamRequestsTotal.WithLabelValues(fqdn, upstreamLabel, "error").Inc()
			// Passive Health Check (Connection Failure)
			if tenant.Security.CircuitBreaker.Enabled && r.Context().Err() == nil &&
				!errors.Is(err, context.Canceled) && !errors.Is(err, errResponseInspection) {
				h.recordUpstreamFailure(upstream, tenant.Security.CircuitBreaker.Threshold, tenant.Security.CircuitBreaker.Cooldown)
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}

		upstreams = append(upstreams, upstream)

	}

	if len(upstreams) == 0 {
		return nil, fmt.Errorf("tenant %s must define at least one valid upstream", fqdn)
	}

	tenantState := &TenantState{upstreams: upstreams}
	return tenantState, nil
}

func (h *ProxyHandler) replaceTenantStates(next map[string]*TenantState) {
	var previous []*TenantState
	h.tenantStates.Range(func(key, value any) bool {
		previous = append(previous, value.(*TenantState))
		h.tenantStates.Delete(key)
		return true
	})
	retained := make(map[[2]string]bool)
	for fqdn, state := range next {
		h.tenantStates.Store(fqdn, state)
		for _, upstream := range state.upstreams {
			retained[[2]string{upstream.Tenant, upstream.URL.Redacted()}] = true
		}
	}
	closeTenantStates(previous, retained)
}

// closeTenantStates releases replaced tenant states. Metric series of
// upstreams that the next configuration keeps are left in place.
func closeTenantStates(states []*TenantState, retained map[[2]string]bool) {
	for _, state := range states {
		for _, upstream := range state.upstreams {
			labels := [2]string{upstream.Tenant, upstream.URL.Redacted()}
			if retained[labels] {
				continue
			}
			upstreamHealthy.DeleteLabelValues(labels[0], labels[1])
			upstreamRequestsTotal.DeletePartialMatch(prometheus.Labels{"tenant": labels[0], "upstream": labels[1]})
		}
	}
	closeTenantStateTransports(states)
}

func closeTenantStateTransports(states []*TenantState) {
	for _, state := range states {
		for _, upstream := range state.upstreams {
			if upstream.Transport != nil {
				upstream.Transport.CloseIdleConnections()
			}
		}
	}
}

// probeTenantStates checks every upstream once, in parallel, and waits for the
// results. Reload calls it before publishing so new tenants never serve
// traffic with unknown upstream health.
func (h *ProxyHandler) probeTenantStates(states map[string]*TenantState) {
	var wg sync.WaitGroup
	for _, state := range states {
		for _, upstream := range state.upstreams {
			wg.Go(func() {
				h.performCheck(upstream)
			})
		}
	}
	wg.Wait()
}

func (h *ProxyHandler) startHealthChecksForStates(ctx context.Context, states map[string]*TenantState) {
	for _, state := range states {
		for _, upstream := range state.upstreams {
			go h.healthCheck(ctx, upstream)
		}
	}
}

func (h *ProxyHandler) healthCheck(ctx context.Context, upstream *UpstreamServer) {
	interval := upstream.healthCheck.Interval
	if interval <= 0 {
		interval = defaultHealthCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.performCheck(upstream)
		}
	}
}

func (h *ProxyHandler) crowdSecHealthCheck(ctx context.Context, bouncer *csbouncer.LiveBouncer) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, securityDependencyTimeout)
			_, err := bouncer.Get(probeCtx, "127.0.0.1")
			cancel()
			h.crowdsecHealthy.Store(err == nil)
		}
	}
}

// checkUpstream runs one active health check: an HTTP GET when a path is
// configured, otherwise a TCP connect.
func checkUpstream(upstream *UpstreamServer) error {
	timeout := upstream.healthCheck.Timeout
	if timeout <= 0 {
		timeout = defaultHealthCheckTimeout
	}
	if upstream.healthCheck.Path == "" || upstream.healthClient == nil {
		conn, err := net.DialTimeout("tcp", upstreamDialAddress(upstream.URL), timeout)
		if err != nil {
			return err
		}
		return conn.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	checkURL := upstream.URL.JoinPath(upstream.healthCheck.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "synit-waf-healthcheck")
	resp, err := upstream.healthClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

func (h *ProxyHandler) performCheck(upstream *UpstreamServer) {
	if err := checkUpstream(upstream); err != nil {
		upstreamHealthy.WithLabelValues(upstream.Tenant, upstream.URL.Redacted()).Set(0)
		if upstream.isHealthy.Load() {
			ErrorLog.WithField("upstream", upstream.URL.Redacted()).Warnf("Upstream is down: %v", err)
			upstream.isHealthy.Store(false)
		}
		return
	}

	upstreamHealthy.WithLabelValues(upstream.Tenant, upstream.URL.Redacted()).Set(1)
	if !upstream.isHealthy.Load() {
		ErrorLog.WithField("upstream", upstream.URL.Redacted()).Info("Upstream is back up")
		upstream.isHealthy.Store(true)
	}
}

func upstreamDialAddress(target *url.URL) string {
	if target.Port() != "" {
		return target.Host
	}
	port := "80"
	if target.Scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(target.Hostname(), port)
}

// contextKey is a custom type to avoid context key collisions.
type contextKey string

const authenticatedUserKey contextKey = "authenticatedUser"

// dummyBcryptHash is compared against when the user name is unknown, so the
// response time does not reveal which user names exist.
var dummyBcryptHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("synit-waf-unknown-user"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("generate dummy bcrypt hash: %v", err))
	}
	return hash
})

func (h *ProxyHandler) basicAuthCacheKey(user, pass, hash string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, h.basicAuthKey)
	for _, part := range []string{user, pass, hash} {
		_, _ = mac.Write([]byte(strconv.Itoa(len(part))))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(part))
	}
	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))
	return key
}

// checkBasicAuth checks the request for valid basic auth credentials.
// It currently supports bcrypt password hashes only.
// If successful, it returns a new context with the username stored.
func (h *ProxyHandler) checkBasicAuth(r *http.Request, credentials []BasicAuthCredentials) (bool, *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false, r
	}

	authenticated := false
	userKnown := false
	for _, cred := range credentials {
		if user != cred.User {
			continue
		}
		userKnown = true
		cacheKey := h.basicAuthCacheKey(user, pass, cred.Password)
		if _, cached := h.basicAuthCache.Get(cacheKey); cached {
			authenticated = true
			break
		}
		// Note: This only supports bcrypt hashes. If other formats are needed,
		// a more comprehensive htpasswd library or custom logic is required.
		if bcrypt.CompareHashAndPassword([]byte(cred.Password), []byte(pass)) == nil {
			h.basicAuthCache.Add(cacheKey, struct{}{})
			authenticated = true
			break
		}
	}
	if !userKnown {
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash(), []byte(pass))
	}
	if !authenticated {
		return false, r
	}

	if info := requestInfoFrom(r); info != nil {
		info.user = user
	}
	newCtx := context.WithValue(r.Context(), authenticatedUserKey, user)
	return true, r.WithContext(newCtx)
}

// disruptiveActionPattern finds a blocking action in a raw rule after quoted
// values such as msg and logdata were removed.
var (
	quotedRuleValuePattern  = regexp.MustCompile(`'[^']*'`)
	disruptiveActionPattern = regexp.MustCompile(`(?:^|[,"\s])(?:deny|drop|redirect)(?:[,:"\s]|$)`)
)

// wouldDisrupt reports whether a matched rule blocks when the engine is on.
// Coraza reports Disruptive() as false in DetectionOnly mode, so the rule
// text is inspected instead.
func wouldDisrupt(rule types.MatchedRule) bool {
	if rule.Disruptive() {
		return true
	}
	raw := quotedRuleValuePattern.ReplaceAllString(rule.Rule().Raw(), "")
	return disruptiveActionPattern.MatchString(raw)
}

// logMatchedRule is the Coraza error callback. Coraza calls it for every
// matched rule that carries the "log" action, in blocking and in audit mode.
func (h *ProxyHandler) logMatchedRule(rule types.MatchedRule) {
	fields := logrus.Fields{
		"event_id":  rule.TransactionID(),
		"client_ip": rule.ClientIPAddress(),
		"uri":       boundedLogValue(rule.URI()),
		"rule_id":   rule.Rule().ID(),
		"severity":  rule.Rule().Severity().String(),
		"message":   boundedLogValue(rule.Message()),
		"data":      boundedLogValue(rule.Data()),
	}
	tenant := "unmatched"
	if value, ok := h.activeTx.Load(rule.TransactionID()); ok {
		meta := value.(wafTransactionMeta)
		tenant = meta.tenant
		fields["host"] = boundedLogValue(meta.host)
		fields["audit_mode"] = meta.audit
	}
	fields["tenant"] = tenant
	ruleMatchesTotal.WithLabelValues(tenant, strconv.Itoa(rule.Rule().ID())).Inc()
	ErrorLog.WithFields(fields).Warn("WAF rule matched")
}

// applyWAF processes the request through the Coraza WAF.
// It returns true if the request was interrupted (blocked).
func (h *ProxyHandler) applyWAF(w http.ResponseWriter, r *http.Request, waf coraza.WAF) (interrupted bool) {
	tx := waf.NewTransaction()
	entry, tenant, matched := h.tenantFor(r)
	if !matched {
		tenant = "unmatched"
	}
	auditMode := matched && entry.Tenant.Security.AuditMode
	h.activeTx.Store(tx.ID(), wafTransactionMeta{tenant: tenant, host: r.Host, audit: auditMode})
	clientIP := h.clientIPFor(r)
	defer func() {
		if auditMode {
			h.recordAuditDetection(tx, tenant, clientIP, r.Host)
		}
		tx.ProcessLogging()
		_ = tx.Close()
		h.activeTx.Delete(tx.ID())
	}()

	// Process Connection
	tx.ProcessConnection(clientIP, 0, "", 0)
	if tx.IsInterrupted() {
		h.blockRequest(w, r, tx, "Connection Phase")
		return true
	}

	// Process URI
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	if tx.IsInterrupted() {
		h.blockRequest(w, r, tx, "URI Phase")
		return true
	}

	// Process Request Headers
	tx.AddRequestHeader("Host", r.Host)
	for k, vr := range r.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.ProcessRequestHeaders()
	if tx.IsInterrupted() {
		h.blockRequest(w, r, tx, "Header Phase")
		return true
	}

	// Process Request Body
	if r.Body != nil && r.ContentLength != 0 {
		if hasUnsupportedContentEncoding(r) {
			blockedTotal.WithLabelValues("request_content_encoding", tenant).Inc()
			http.Error(w, "Compressed request bodies cannot be inspected", http.StatusUnsupportedMediaType)
			return true
		}
		limit := h.requestBodyLimit.Load()
		if limit <= 0 {
			limit = defaultRequestBodyCap
		}
		bodyBytes, err := h.inspectionBody(r, limit)
		if errors.Is(err, errInspectionBodyTooLarge) {
			blockedTotal.WithLabelValues("request_body_oversize", tenant).Inc()
			http.Error(w, "Request body exceeds inspection limit", http.StatusRequestEntityTooLarge)
			return true
		}
		if err != nil {
			ErrorLog.WithField("client_ip", clientIP).Errorf("failed to read request body: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return true
		}

		if _, _, err := tx.WriteRequestBody(bodyBytes); err != nil {
			ErrorLog.WithField("client_ip", clientIP).Errorf("failed to write request body to WAF: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return true
		}
	}

	// Coraza evaluates phase 2 rules inside ProcessRequestBody, also for an
	// empty body. Skipping the call for bodiless requests would disable every
	// phase 2 rule, including the OWASP CRS blocking evaluation, on GET.
	if _, err := tx.ProcessRequestBody(); err != nil {
		ErrorLog.WithField("client_ip", clientIP).Errorf("WAF request body processing failed: %v", err)
		http.Error(w, "Request body security inspection failed", http.StatusInternalServerError)
		return true
	}
	if tx.IsInterrupted() {
		h.blockRequest(w, r, tx, "Body Phase")
		return true
	}

	return false
}

// recordAuditDetection counts and logs a request that matched a blocking rule
// while the tenant runs in audit mode, where Coraza never interrupts.
func (h *ProxyHandler) recordAuditDetection(tx types.Transaction, tenant, clientIP, host string) {
	for _, rule := range tx.MatchedRules() {
		if !wouldDisrupt(rule) {
			continue
		}
		auditModeEventsTotal.WithLabelValues(tenant).Inc()
		ErrorLog.WithFields(logrus.Fields{
			"client_ip": clientIP,
			"host":      boundedLogValue(host),
			"tenant":    tenant,
			"rule_id":   rule.Rule().ID(),
			"event_id":  tx.ID(),
		}).Warn("WAF attack detected (Audit Mode)")
		return
	}
}

func hasUnsupportedContentEncoding(r *http.Request) bool {
	encoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	return encoding != "" && !strings.EqualFold(encoding, "identity")
}

func (h *ProxyHandler) rejectInspectionOversize(w http.ResponseWriter, r *http.Request, control string) {
	blockedTotal.WithLabelValues(control+"_oversize", h.metricTenant(r)).Inc()
	http.Error(w, "Request body exceeds inspection limit", http.StatusRequestEntityTooLarge)
}

func (h *ProxyHandler) metricTenant(r *http.Request) string {
	_, matchedDomain, ok := h.tenantFor(r)
	if !ok {
		return "unmatched"
	}
	return matchedDomain
}

// blockRequest logs and writes the WAF block response.
func (h *ProxyHandler) blockRequest(w http.ResponseWriter, r *http.Request, tx types.Transaction, phase string) {
	ruleID := "unknown"
	if matchedRules := tx.MatchedRules(); len(matchedRules) > 0 {
		// The interrupting rule is the last one Coraza matched.
		ruleID = strconv.Itoa(matchedRules[len(matchedRules)-1].Rule().ID())
	}
	if interruption := tx.Interruption(); interruption != nil && interruption.RuleID != 0 {
		ruleID = strconv.Itoa(interruption.RuleID)
	}

	entry, matchedDomain, ok := h.tenantFor(r)
	if !ok {
		matchedDomain = "unmatched"
	}

	ErrorLog.WithFields(logrus.Fields{
		"client_ip": h.clientIPFor(r),
		"host":      boundedLogValue(r.Host),
		"phase":     phase,
		"rule_id":   ruleID,
		"event_id":  tx.ID(),
	}).Info("WAF blocked request")
	blockedTotal.WithLabelValues("waf", matchedDomain).Inc()

	// 2. Custom Block Page Logic
	if entry.Tenant.Security.BlockPageURL != "" {
		http.Redirect(w, r, entry.Tenant.Security.BlockPageURL, http.StatusFound)
		return
	}

	if len(entry.BlockPage) > 0 {
		// The page was loaded at reload time. Placeholder values are escaped
		// because Host is client controlled.
		page := strings.ReplaceAll(string(entry.BlockPage), "{{EVENT_ID}}", html.EscapeString(tx.ID()))
		page = strings.ReplaceAll(page, "{{HOST}}", html.EscapeString(r.Host))

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(page))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(fmt.Appendf(nil, `{"error": "Forbidden by security policy", "event_id": "%s"}`, tx.ID()))
}

func statusClassLabel(statusCode int) string {
	switch {
	case statusCode >= 100 && statusCode < 200:
		return "1xx"
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500 && statusCode < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

func (h *ProxyHandler) setDependencyFailMode(mode string) {
	h.dependencyMode.Store(normalizeDependencyFailMode(mode))
}

func (h *ProxyHandler) getDependencyFailMode() string {
	current := h.dependencyMode.Load()
	if current == nil {
		return dependencyFailOpen
	}
	if mode, ok := current.(string); ok {
		return mode
	}
	return dependencyFailOpen
}

func (h *ProxyHandler) allowRateLimitedRequest(tenant, clientIP string, policy RateLimitPolicy) bool {
	if policy.RequestsPerMinute <= 0 {
		return true
	}

	key := tenant + ":" + rateLimitClientKey(clientIP)

	// Try Distributed Rate Limiting (Native RPC Coordinator)
	if coord := h.coordinator.Load(); coord != nil {
		perSecond := float64(policy.RequestsPerMinute) / 60.0
		allowed, err := coord.Allow(key, perSecond, policy.Burst)
		if err != nil {
			h.coordinatorLog.Do(func() {
				ErrorLog.Warnf("Coordinator rate limit check failed for %s: %v. Falling back to local.", key, err)
			})
		} else {
			return allowed
		}
	}

	// Local Fallback (LRU)
	if entryValue, ok := h.rateLimiters.Get(key); ok {
		if entryValue.requestsPerMinute == policy.RequestsPerMinute && entryValue.burst == policy.Burst {
			return entryValue.limiter.Allow()
		}
	}

	h.rateLimiterMu.Lock()
	defer h.rateLimiterMu.Unlock()
	if entryValue, ok := h.rateLimiters.Get(key); ok {
		if entryValue.requestsPerMinute == policy.RequestsPerMinute && entryValue.burst == policy.Burst {
			return entryValue.limiter.Allow()
		}
	}

	perSecond := rate.Limit(float64(policy.RequestsPerMinute) / 60.0)
	replacement := &rateLimiterState{
		requestsPerMinute: policy.RequestsPerMinute,
		burst:             policy.Burst,
		limiter:           rate.NewLimiter(perSecond, policy.Burst),
	}
	h.rateLimiters.Add(key, replacement)
	return replacement.limiter.Allow()
}

// crowdSecBanned asks CrowdSec LAPI whether clientIP is banned. Verdicts are
// cached for crowdsec.cache_ttl so LAPI is not queried for every request.
func (h *ProxyHandler) crowdSecBanned(ctx context.Context, bouncer *csbouncer.LiveBouncer, clientIP string) (bool, error) {
	ttl := time.Duration(h.crowdsecCacheTTL.Load())
	now := time.Now()
	if ttl > 0 {
		if decision, ok := h.crowdsecCache.Get(clientIP); ok && now.Before(decision.expires) {
			return decision.banned, nil
		}
	}
	dependencyCtx, cancel := context.WithTimeout(ctx, securityDependencyTimeout)
	decisions, err := bouncer.Get(dependencyCtx, clientIP)
	cancel()
	h.crowdsecHealthy.Store(err == nil)
	if err != nil {
		return false, err
	}
	banned := decisions != nil && len(*decisions) > 0
	if ttl > 0 {
		h.crowdsecCache.Add(clientIP, crowdsecDecision{banned: banned, expires: now.Add(ttl)})
	}
	return banned, nil
}
