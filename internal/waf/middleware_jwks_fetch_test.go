package waf

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testJWKS = `{"keys":[{"kid":"test","kty":"RSA","n":"AQID","e":"AQAB"}]}`

func TestGetJWKSCoalescesConcurrentRefresh(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte(testJWKS))
	}))
	defer server.Close()

	h := NewProxyHandler(NewWAFRegistry())
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Go(func() {
			_, err := h.getJWKS(context.Background(), server.URL)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("get JWKS: %v", err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one coalesced request, got %d", got)
	}
}

func TestGetJWKSRefreshesDifferentEndpointsConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	newServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			started <- struct{}{}
			<-release
			_, _ = w.Write([]byte(testJWKS))
		}))
	}
	first := newServer()
	defer first.Close()
	second := newServer()
	defer second.Close()

	h := NewProxyHandler(NewWAFRegistry())
	errs := make(chan error, 2)
	go func() {
		_, err := h.getJWKS(context.Background(), first.URL)
		errs <- err
	}()
	go func() {
		_, err := h.getJWKS(context.Background(), second.URL)
		errs <- err
	}()

	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("different JWKS endpoints were refreshed serially")
		}
	}
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("get JWKS: %v", err)
		}
	}
}

func TestValidateJWTRefreshesJWKSForUnknownKey(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	var response atomic.Value
	response.Store(jwksForRSAKey("old", &oldKey.PublicKey))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(response.Load().(string)))
	}))
	defer server.Close()

	h := NewProxyHandler(NewWAFRegistry())
	if _, err := h.getJWKS(context.Background(), server.URL); err != nil {
		t.Fatalf("prime JWKS: %v", err)
	}
	response.Store(jwksForRSAKey("new", &newKey.PublicKey))

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "issuer",
		"aud": "audience",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	token.Header["kid"] = "new"
	signed, err := token.SignedString(newKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	w := httptest.NewRecorder()
	cfg := struct {
		Enabled      bool   `yaml:"enabled"`
		JWKSEndpoint string `yaml:"jwks_endpoint"`
		Issuer       string `yaml:"issuer"`
		Audience     string `yaml:"audience"`
	}{Enabled: true, JWKSEndpoint: server.URL, Issuer: "issuer", Audience: "audience"}
	if !h.validateJWT(w, req, cfg) {
		t.Fatalf("expected rotated key to validate, status=%d body=%q", w.Code, w.Body.String())
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected one forced refresh after the priming request, got %d requests", got)
	}
}

func TestJWKSCacheIsBounded(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	now := time.Now()
	for i := range maxJWKSCacheEntries + 10 {
		h.storeJWKSCacheEntry(fmt.Sprintf("https://keys-%d.example.com", i), &jwksCacheEntry{
			keys:      map[string]any{"key": i},
			expiresAt: now.Add(time.Hour + time.Duration(i)*time.Second),
		})
	}
	count := 0
	h.jwksCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count > maxJWKSCacheEntries {
		t.Fatalf("expected at most %d cached endpoints, got %d", maxJWKSCacheEntries, count)
	}
}

func TestGetJWKSRejectsOversizeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, testJWKS+strings.Repeat(" ", 2<<20))
	}))
	defer server.Close()

	h := NewProxyHandler(NewWAFRegistry())
	if _, err := h.getJWKS(context.Background(), server.URL); err == nil {
		t.Fatal("expected oversized JWKS response to be rejected")
	}
}

func TestGetJWKSCapsCacheTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=86400")
		_, _ = w.Write([]byte(testJWKS))
	}))
	defer server.Close()

	h := NewProxyHandler(NewWAFRegistry())
	if _, err := h.getJWKS(context.Background(), server.URL); err != nil {
		t.Fatalf("get JWKS: %v", err)
	}
	entryValue, ok := h.jwksCache.Load(server.URL)
	if !ok {
		t.Fatal("expected cached JWKS")
	}
	entry := entryValue.(*jwksCacheEntry)
	if remaining := time.Until(entry.expiresAt); remaining > time.Hour+time.Second {
		t.Fatalf("expected TTL cap of one hour, got %v", remaining)
	}
}

func jwksForRSAKey(kid string, key *rsa.PublicKey) string {
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	modulus := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	return fmt.Sprintf(`{"keys":[{"kid":%q,"kty":"RSA","n":%q,"e":%q}]}`, kid, modulus, exponent)
}
