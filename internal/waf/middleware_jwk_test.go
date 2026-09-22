package waf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestParseJWKECPublicKey(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{name: "P-256", curve: elliptic.P256()},
		{name: "P-384", curve: elliptic.P384()},
		{name: "P-521", curve: elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate EC key: %v", err)
			}
			publicKey, err := privateKey.PublicKey.Bytes()
			if err != nil {
				t.Fatalf("encode EC public key: %v", err)
			}
			coordinateSize := (len(publicKey) - 1) / 2
			jwk := map[string]any{
				"kty": "EC",
				"crv": tt.name,
				"x":   base64.RawURLEncoding.EncodeToString(publicKey[1 : 1+coordinateSize]),
				"y":   base64.RawURLEncoding.EncodeToString(publicKey[1+coordinateSize:]),
			}

			parsed, err := parseJWK(jwk)
			if err != nil {
				t.Fatalf("parse EC JWK: %v", err)
			}
			parsedKey, ok := parsed.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", parsed)
			}
			if !privateKey.PublicKey.Equal(parsedKey) {
				t.Fatal("parsed EC public key does not match source key")
			}
		})
	}
}

func TestParseJWKRejectsInvalidECPoint(t *testing.T) {
	coordinate := make([]byte, 32)
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(coordinate),
		"y":   base64.RawURLEncoding.EncodeToString(coordinate),
	}

	if _, err := parseJWK(jwk); err == nil {
		t.Fatal("expected invalid EC point to be rejected")
	}
}
