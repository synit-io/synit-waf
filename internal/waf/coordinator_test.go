package waf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoordinatorReplacesChangedPolicy(t *testing.T) {
	c := NewCoordinator("leader", "127.0.0.1:0", "secret")
	first := &CheckLimitReply{}
	if err := c.CheckLimit(&CheckLimitArgs{Key: "tenant:client", Limit: 1, Burst: 1, Secret: "secret"}, first); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if !first.Allowed {
		t.Fatal("expected first request to be allowed")
	}

	changed := &CheckLimitReply{}
	if err := c.CheckLimit(&CheckLimitArgs{Key: "tenant:client", Limit: 1000, Burst: 2, Secret: "secret"}, changed); err != nil {
		t.Fatalf("changed-policy check: %v", err)
	}
	if !changed.Allowed {
		t.Fatal("expected changed policy to replace stale limiter")
	}
}

func TestCoordinatorBoundsLimiterKeys(t *testing.T) {
	c := NewCoordinator("leader", "127.0.0.1:0", "secret")
	c.maxEntries = 2
	for _, key := range []string{"one", "two", "three"} {
		if err := c.CheckLimit(&CheckLimitArgs{Key: key, Limit: 1, Burst: 1, Secret: "secret"}, &CheckLimitReply{}); err != nil {
			t.Fatalf("check %s: %v", key, err)
		}
	}
	if got := len(c.limiters); got > 2 {
		t.Fatalf("expected at most two limiter keys, got %d", got)
	}
}

func TestCoordinatorAmortizesExpiredLimiterCleanup(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewCoordinator("leader", "127.0.0.1:0", "secret")
	c.entryTTL = 10 * time.Minute
	c.now = func() time.Time { return now }
	c.limiters["expired"] = &coordinatorLimiter{lastSeen: now.Add(-11 * time.Minute)}

	if err := c.CheckLimit(&CheckLimitArgs{Key: "current", Limit: 1, Burst: 1, Secret: "secret"}, &CheckLimitReply{}); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if _, ok := c.limiters["expired"]; ok {
		t.Fatal("expected expired entry to be removed")
	}

	c.limiters["expired-later"] = &coordinatorLimiter{lastSeen: now.Add(-11 * time.Minute)}
	now = now.Add(30 * time.Second)
	if err := c.CheckLimit(&CheckLimitArgs{Key: "another", Limit: 1, Burst: 1, Secret: "secret"}, &CheckLimitReply{}); err != nil {
		t.Fatalf("check before cleanup interval: %v", err)
	}
	if _, ok := c.limiters["expired-later"]; !ok {
		t.Fatal("cleanup ran before its amortized interval")
	}

	now = now.Add(31 * time.Second)
	if err := c.CheckLimit(&CheckLimitArgs{Key: "final", Limit: 1, Burst: 1, Secret: "secret"}, &CheckLimitReply{}); err != nil {
		t.Fatalf("check after cleanup interval: %v", err)
	}
	if _, ok := c.limiters["expired-later"]; ok {
		t.Fatal("expected cleanup after its amortized interval")
	}
}

func TestCoordinatorRequiresTLS(t *testing.T) {
	c := NewCoordinator("leader", "127.0.0.1:0", "secret")
	if err := c.Start(); err == nil {
		t.Fatal("expected leader startup without TLS to fail")
	}
}

func TestCoordinatorRPCUsesTLS(t *testing.T) {
	caFile, certFile, keyFile := writeCoordinatorTestCertificates(t)
	leader := NewCoordinator("leader", "127.0.0.1:0", "secret")
	if err := leader.ConfigureTLS("", certFile, keyFile, ""); err != nil {
		t.Fatalf("configure leader TLS: %v", err)
	}
	if err := leader.Start(); err != nil {
		t.Fatalf("start leader: %v", err)
	}
	t.Cleanup(func() { _ = leader.Close() })

	follower := NewCoordinator("follower", leader.listener.Addr().String(), "secret")
	if err := follower.ConfigureTLS(caFile, "", "", "localhost"); err != nil {
		t.Fatalf("configure follower TLS: %v", err)
	}
	if err := follower.Start(); err != nil {
		t.Fatalf("start follower: %v", err)
	}
	t.Cleanup(func() { _ = follower.Close() })
	allowed, err := follower.Allow("tenant:client", 1000, 10)
	if err != nil {
		t.Fatalf("TLS RPC: %v", err)
	}
	if !allowed {
		t.Fatal("expected first rate-limit request to be allowed")
	}
	firstConn := follower.clientConn
	if allowed, err = follower.Allow("tenant:other-client", 1000, 10); err != nil || !allowed {
		t.Fatalf("second TLS RPC: allowed=%v err=%v", allowed, err)
	}
	if follower.clientConn != firstConn {
		t.Fatal("expected follower to reuse its RPC connection")
	}
}

func TestCoordinatorFollowerReconnectsAfterConnectionFailure(t *testing.T) {
	caFile, certFile, keyFile := writeCoordinatorTestCertificates(t)
	leader := NewCoordinator("leader", "127.0.0.1:0", "secret")
	if err := leader.ConfigureTLS("", certFile, keyFile, ""); err != nil {
		t.Fatalf("configure leader TLS: %v", err)
	}
	if err := leader.Start(); err != nil {
		t.Fatalf("start leader: %v", err)
	}
	t.Cleanup(func() { _ = leader.Close() })

	follower := NewCoordinator("follower", leader.listener.Addr().String(), "secret")
	if err := follower.ConfigureTLS(caFile, "", "", "localhost"); err != nil {
		t.Fatalf("configure follower TLS: %v", err)
	}
	t.Cleanup(func() { _ = follower.Close() })
	if _, err := follower.Allow("first", 1000, 10); err != nil {
		t.Fatalf("first call: %v", err)
	}
	firstConn := follower.clientConn
	if err := firstConn.Close(); err != nil {
		t.Fatalf("close follower connection: %v", err)
	}
	if _, err := follower.Allow("failed", 1000, 10); err == nil {
		t.Fatal("expected the broken connection call to fail")
	}
	if _, err := follower.Allow("reconnected", 1000, 10); err != nil {
		t.Fatalf("reconnected call: %v", err)
	}
	if follower.clientConn == firstConn {
		t.Fatal("expected a new connection after failure")
	}
}

func TestCoordinatorClosePreventsFollowerRedial(t *testing.T) {
	c := NewCoordinator("follower", "127.0.0.1:1", "secret")
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := c.Allow("key", 1, 1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed error, got %v", err)
	}
}

func TestCoordinatorSupportsMutualTLS(t *testing.T) {
	caFile, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile := writeCoordinatorMTLSCertificates(t)
	leader := NewCoordinator("leader", "127.0.0.1:0", "secret")
	if err := leader.ConfigureTLS(caFile, serverCertFile, serverKeyFile, ""); err != nil {
		t.Fatalf("configure mTLS leader: %v", err)
	}
	if err := leader.Start(); err != nil {
		t.Fatalf("start mTLS leader: %v", err)
	}
	t.Cleanup(func() { _ = leader.Close() })

	unauthenticated := NewCoordinator("follower", leader.listener.Addr().String(), "secret")
	if err := unauthenticated.ConfigureTLS(caFile, "", "", "localhost"); err != nil {
		t.Fatalf("configure unauthenticated follower: %v", err)
	}
	if _, err := unauthenticated.Allow("unauthenticated", 1, 1); err == nil {
		t.Fatal("expected leader to reject follower without a client certificate")
	}
	_ = unauthenticated.Close()

	follower := NewCoordinator("follower", leader.listener.Addr().String(), "secret")
	if err := follower.ConfigureTLS(caFile, clientCertFile, clientKeyFile, "localhost"); err != nil {
		t.Fatalf("configure mTLS follower: %v", err)
	}
	t.Cleanup(func() { _ = follower.Close() })
	if allowed, err := follower.Allow("authenticated", 1, 1); err != nil || !allowed {
		t.Fatalf("mTLS RPC: allowed=%v err=%v", allowed, err)
	}
}

func writeCoordinatorTestCertificates(t *testing.T) (string, string, string) {
	t.Helper()
	caFile, certFile, keyFile, _, _ := writeCoordinatorMTLSCertificates(t)
	return caFile, certFile, keyFile
}

func writeCoordinatorMTLSCertificates(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-follower"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	clientCertFile := filepath.Join(dir, "client.pem")
	clientKeyFile := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA certificate: %v", err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}), 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}
	if err := os.WriteFile(clientCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600); err != nil {
		t.Fatalf("write client certificate: %v", err)
	}
	if err := os.WriteFile(clientKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	return caFile, certFile, keyFile, clientCertFile, clientKeyFile
}
