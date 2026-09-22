package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchConfigReloadsTenantShardChanges(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	path := writeReloadConfig(t, dir, upstream.URL, "", "SecRuleEngine On")
	shards := filepath.Join(dir, "tenants.d")
	if err := os.Mkdir(shards, 0o700); err != nil {
		t.Fatalf("create shards: %v", err)
	}

	registry := NewWAFRegistry()
	h := NewProxyHandler(registry)
	if err := registry.Reload(path, h); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	ctx := t.Context()
	ready := make(chan struct{})
	go watchConfig(ctx, registry, path, h, ready)
	<-ready

	shard := fmt.Sprintf(`tenants:
  "shard.example.com":
    upstreams:
      - url: %q
    security:
      waf_enabled: false
`, upstream.URL)
	if err := os.WriteFile(filepath.Join(shards, "tenant.yml"), []byte(shard), 0o600); err != nil {
		t.Fatalf("write shard: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := registry.Get("shard.example.com"); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("tenant shard change did not trigger reload")
}

func TestWatchConfigHandlesTenantDirectoryRecreation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	path := writeReloadConfig(t, dir, upstream.URL, "", "SecRuleEngine On")
	shards := filepath.Join(dir, "tenants.d")
	if err := os.Mkdir(shards, 0o700); err != nil {
		t.Fatalf("create shards: %v", err)
	}

	registry := NewWAFRegistry()
	h := NewProxyHandler(registry)
	if err := registry.Reload(path, h); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	ctx := t.Context()
	ready := make(chan struct{})
	go watchConfig(ctx, registry, path, h, ready)
	<-ready

	if err := os.Remove(shards); err != nil {
		t.Fatalf("remove empty shard directory: %v", err)
	}
	if err := os.Mkdir(shards, 0o700); err != nil {
		t.Fatalf("recreate shards: %v", err)
	}
	shard := fmt.Sprintf(`tenants:
  "recreated.example.com":
    upstreams:
      - url: %q
    security:
      waf_enabled: false
`, upstream.URL)
	if err := os.WriteFile(filepath.Join(shards, "tenant.yml"), []byte(shard), 0o600); err != nil {
		t.Fatalf("write recreated shard: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := registry.Get("recreated.example.com"); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recreated tenant shard directory was not watched")
}
