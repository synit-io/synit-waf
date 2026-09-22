package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/synit-io/synit-waf/internal/waf"
)

func TestConfigureACMERecordsAgreementAndStaging(t *testing.T) {
	previous := certmagic.DefaultACME
	defer func() { certmagic.DefaultACME = previous }()

	var cfg waf.AppConfig
	cfg.GlobalSettings.ACME.Email = "ops@example.com"
	cfg.GlobalSettings.ACME.AgreeTOS = true
	cfg.GlobalSettings.ACME.Staging = true
	configureACME(cfg)

	// Without Agreed, certmagic prompts on stdin during account registration.
	if !certmagic.DefaultACME.Agreed {
		t.Fatal("expected the subscriber agreement to be recorded")
	}
	if certmagic.DefaultACME.Email != "ops@example.com" || certmagic.DefaultACME.CA != certmagic.LetsEncryptStagingCA {
		t.Fatalf("unexpected ACME defaults: %+v", certmagic.DefaultACME)
	}
}

func TestACMEHTTPHandlerRedirectsToHTTPS(t *testing.T) {
	handler := acmeHTTPHandler(certmagic.New(certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return &certmagic.Config{}, nil },
	}), certmagic.Config{}))
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com:80/path?x=1", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://api.example.com/path?x=1" {
		t.Fatalf("expected an HTTPS redirect, got %d %q", w.Code, w.Header().Get("Location"))
	}
}
