package waf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchConfig watches the main config and tenant shards for changes.
func WatchConfig(ctx context.Context, registry *SafeWAFRegistry, path string, h *ProxyHandler) {
	watchConfig(ctx, registry, path, h, nil)
}

func watchConfig(ctx context.Context, registry *SafeWAFRegistry, path string, h *ProxyHandler, ready chan<- struct{}) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		ErrorLog.Errorf("Failed to create config watcher: %v", err)
		if ready != nil {
			close(ready)
		}
		return
	}
	defer func() { _ = watcher.Close() }()

	mainPath, err := filepath.Abs(path)
	if err != nil {
		ErrorLog.Errorf("Failed to resolve config path: %v", err)
		if ready != nil {
			close(ready)
		}
		return
	}
	configDir := filepath.Dir(mainPath)
	tenantsDir := filepath.Join(configDir, "tenants.d")
	watched := make(map[string]bool)
	addWatch := func(directory string) error {
		if watched[directory] {
			return nil
		}
		if err := watcher.Add(directory); err != nil {
			return err
		}
		watched[directory] = true
		return nil
	}
	if err := addWatch(configDir); err != nil {
		ErrorLog.Errorf("Failed to watch config directory: %v", err)
		if ready != nil {
			close(ready)
		}
		return
	}
	if info, err := os.Stat(tenantsDir); err == nil && info.IsDir() {
		if err := addWatch(tenantsDir); err != nil {
			ErrorLog.Errorf("Failed to watch tenant shard directory: %v", err)
			if ready != nil {
				close(ready)
			}
			return
		}
	}
	if ready != nil {
		close(ready)
	}

	var timer *time.Timer
	var timerC <-chan time.Time
	scheduleReload := func() {
		if timer == nil {
			timer = time.NewTimer(100 * time.Millisecond)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(100 * time.Millisecond)
		}
		timerC = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			eventPath, err := filepath.Abs(event.Name)
			if err != nil {
				continue
			}
			if eventPath == tenantsDir {
				if event.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
					delete(watched, tenantsDir)
				}
				if event.Op&fsnotify.Create != 0 {
					if err := addWatch(tenantsDir); err != nil {
						ErrorLog.Errorf("Failed to watch new tenant shard directory: %v", err)
					}
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
					scheduleReload()
				}
				continue
			}
			isMain := eventPath == mainPath
			isShard := filepath.Dir(eventPath) == tenantsDir &&
				(strings.HasSuffix(eventPath, ".yml") || strings.HasSuffix(eventPath, ".yaml"))
			if (isMain || isShard) && event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
				scheduleReload()
			}
		case <-timerC:
			timerC = nil
			ErrorLog.Info("Configuration changed. Reloading...")
			if err := registry.Reload(mainPath, h); err != nil {
				ErrorLog.Errorf("Failed to reload configuration: %v", err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			ErrorLog.Errorf("Config watcher error: %v", err)
		}
	}
}
