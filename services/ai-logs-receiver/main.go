package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultMaxRequestBytes     = 10 << 20
	defaultMaxTenantBytes      = 1 << 30
	defaultRequestsPerMinute   = 600
	defaultLogRetention        = 30 * 24 * time.Hour
	logReceiverShutdownTimeout = 30 * time.Second
	retentionSweepInterval     = 6 * time.Hour
	minTokenLength             = 32
	authFailureWindow          = time.Minute
	maxAuthFailures            = 10
	maxAuthFailureClients      = 4096
	readinessCacheInterval     = 5 * time.Second
)

var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func loadTenantTokens(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("AI_LOG_TOKENS is required")
	}

	var tokens map[string]string
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return nil, fmt.Errorf("parse AI_LOG_TOKENS: %w", err)
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("AI_LOG_TOKENS must contain at least one tenant token")
	}
	seenTokens := make(map[string]string, len(tokens))
	for tenantID, token := range tokens {
		if !tenantIDPattern.MatchString(tenantID) || filepath.Base(tenantID) != tenantID {
			return nil, fmt.Errorf("AI_LOG_TOKENS contains invalid tenant ID %q", tenantID)
		}
		if len(strings.TrimSpace(token)) < minTokenLength {
			return nil, fmt.Errorf("AI_LOG_TOKENS token for tenant %q must be at least %d characters", tenantID, minTokenLength)
		}
		if otherTenant, exists := seenTokens[token]; exists {
			return nil, fmt.Errorf("AI_LOG_TOKENS reuses one token for tenants %q and %q", otherTenant, tenantID)
		}
		seenTokens[token] = tenantID
	}
	return tokens, nil
}

func getLogsDir() string {
	dir := strings.TrimSpace(os.Getenv("LOGS_DIR"))
	if dir == "" {
		dir = "./logs"
	}
	return dir
}

func tenantIDForToken(tokens map[string]string, candidate string) string {
	for tenantID, token := range tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(candidate)) == 1 {
			return tenantID
		}
	}
	return ""
}

type LogReceiver struct {
	tokens            map[string]string
	logsDir           string
	maxRequestBytes   int64
	maxTenantBytes    int64
	requestsPerMinute int
	retention         time.Duration
	now               func() time.Time
	mu                sync.Mutex
	tenants           map[string]*tenantReceiverState
	authFailures      authFailureLimiter
	readyMu           sync.Mutex
	readyChecked      time.Time
	readyErr          error
}

type tenantReceiverState struct {
	mu          sync.Mutex
	windowStart time.Time
	requests    int
	usedBytes   int64
	usedKnown   bool
}

// allowRequest counts one request in the tenant's fixed one-minute window.
func (s *tenantReceiverState) allowRequest(now time.Time, requestsPerMinute int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windowStart.IsZero() || now.Sub(s.windowStart) >= time.Minute {
		s.windowStart = now
		s.requests = 0
	}
	if s.requests >= requestsPerMinute {
		return false
	}
	s.requests++
	return true
}

// authFailureLimiter throttles remote IPs that keep failing authentication.
// The zero value is ready to use.
type authFailureLimiter struct {
	mu      sync.Mutex
	clients map[string]authFailures
}

type authFailures struct {
	windowStart time.Time
	count       int
}

func (l *authFailureLimiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.clients[ip]
	if !ok {
		return false
	}
	if now.Sub(entry.windowStart) >= authFailureWindow {
		delete(l.clients, ip)
		return false
	}
	return entry.count >= maxAuthFailures
}

func (l *authFailureLimiter) recordFailure(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients == nil {
		l.clients = make(map[string]authFailures)
	}
	entry, ok := l.clients[ip]
	if ok && now.Sub(entry.windowStart) < authFailureWindow {
		entry.count++
		l.clients[ip] = entry
		return
	}
	if !ok && len(l.clients) >= maxAuthFailureClients {
		l.evict(now)
	}
	l.clients[ip] = authFailures{windowStart: now, count: 1}
}

// evict removes expired entries, or one arbitrary entry when none has expired,
// so the map never exceeds maxAuthFailureClients.
func (l *authFailureLimiter) evict(now time.Time) {
	for ip, entry := range l.clients {
		if now.Sub(entry.windowStart) >= authFailureWindow {
			delete(l.clients, ip)
		}
	}
	if len(l.clients) < maxAuthFailureClients {
		return
	}
	for ip := range l.clients {
		delete(l.clients, ip)
		return
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newLogReceiver(tokens map[string]string, logsDir string, maxRequestBytes, maxTenantBytes int64, requestsPerMinute int, retention time.Duration) *LogReceiver {
	return &LogReceiver{
		tokens:            tokens,
		logsDir:           logsDir,
		maxRequestBytes:   maxRequestBytes,
		maxTenantBytes:    maxTenantBytes,
		requestsPerMinute: requestsPerMinute,
		retention:         retention,
		now:               time.Now,
		tenants:           make(map[string]*tenantReceiverState),
	}
}

func (lr *LogReceiver) tenantState(tenantID string) *tenantReceiverState {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if lr.tenants == nil {
		lr.tenants = make(map[string]*tenantReceiverState)
	}
	state := lr.tenants[tenantID]
	if state == nil {
		state = &tenantReceiverState{}
		lr.tenants[tenantID] = state
	}
	return state
}

func (lr *LogReceiver) limits() (string, int64, int64, int, time.Duration, func() time.Time) {
	logsDir := lr.logsDir
	if logsDir == "" {
		logsDir = getLogsDir()
	}
	maxRequestBytes := lr.maxRequestBytes
	if maxRequestBytes <= 0 {
		maxRequestBytes = defaultMaxRequestBytes
	}
	maxTenantBytes := lr.maxTenantBytes
	if maxTenantBytes <= 0 {
		maxTenantBytes = defaultMaxTenantBytes
	}
	requestsPerMinute := lr.requestsPerMinute
	if requestsPerMinute <= 0 {
		requestsPerMinute = defaultRequestsPerMinute
	}
	retention := lr.retention
	if retention <= 0 {
		retention = defaultLogRetention
	}
	now := lr.now
	if now == nil {
		now = time.Now
	}
	return logsDir, maxRequestBytes, maxTenantBytes, requestsPerMinute, retention, now
}

func requireMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, method := range allowed {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (lr *LogReceiver) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	logsDir, maxRequestBytes, maxTenantBytes, requestsPerMinute, _, nowFunc := lr.limits()
	now := nowFunc().UTC()

	clientIP := remoteIP(r)
	if lr.authFailures.blocked(clientIP, now) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		lr.authFailures.recordFailure(clientIP, now)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := authHeader[len("Bearer "):]

	tenantID := tenantIDForToken(lr.tokens, token)
	if tenantID == "" {
		lr.authFailures.recordFailure(clientIP, now)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "application/x-ndjson") {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > maxRequestBytes {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// The rate limit counts requests, not lines, and is settled before the body
	// is read so a slow upload never holds the tenant lock.
	state := lr.tenantState(tenantID)
	if !state.allowRequest(now, requestsPerMinute) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	payload, err := logLines(bodyBytes, mediaType == "application/json")
	if err != nil {
		http.Error(w, "Bad Request: "+err.Error(), http.StatusBadRequest)
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	targetDir := filepath.Join(logsDir, tenantID)
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		log.Printf("Failed to create log directory: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !state.usedKnown {
		usedBytes, err := directoryBytes(targetDir)
		if err != nil {
			log.Printf("Failed to calculate tenant log usage: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		state.usedBytes, state.usedKnown = usedBytes, true
	}
	if state.usedBytes+int64(len(payload)) > maxTenantBytes {
		http.Error(w, "Tenant log storage quota exceeded", http.StatusInsufficientStorage)
		return
	}

	dateStr := now.Format("2006-01-02")
	logFilePath := filepath.Join(targetDir, dateStr+".log")

	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()

	written, err := f.Write(payload)
	state.usedBytes += int64(written)
	if err != nil {
		log.Printf("Failed to write to log file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("Failed to sync log file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// logLines validates a request body and returns it as one JSON value per line,
// each terminated by '\n'. Raw control characters are rejected so a tenant
// cannot forge or visually overwrite stored lines.
func logLines(body []byte, single bool) ([]byte, error) {
	payload := make([]byte, 0, len(body)+1)
	lines := 0
	for line := range bytes.SplitSeq(body, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		lines++
		if bytes.ContainsFunc(line, func(r rune) bool { return r < 0x20 }) {
			return nil, fmt.Errorf("line %d contains a raw control character", lines)
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("line %d is not valid JSON", lines)
		}
		payload = append(payload, line...)
		payload = append(payload, '\n')
	}
	if lines == 0 {
		return nil, errors.New("body contains no JSON")
	}
	if single && lines != 1 {
		return nil, errors.New("application/json body must be a single line; use application/x-ndjson for batches")
	}
	return payload, nil
}

func removeExpiredLogs(dir string, cutoff time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".log" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (lr *LogReceiver) cleanupExpiredLogs() error {
	logsDir, _, _, _, retention, nowFunc := lr.limits()
	entries, err := os.ReadDir(logsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tenantDir := filepath.Join(logsDir, entry.Name())
		state := lr.tenantState(entry.Name())
		state.mu.Lock()
		err := removeExpiredLogs(tenantDir, nowFunc().UTC().Add(-retention))
		// Reconcile the cached usage with the directory; on failure the next
		// write rescans it.
		usedBytes, usedErr := directoryBytes(tenantDir)
		state.usedBytes, state.usedKnown = usedBytes, usedErr == nil
		state.mu.Unlock()
		if err := errors.Join(err, usedErr); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", entry.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (lr *LogReceiver) runRetention(ctx context.Context, interval time.Duration) {
	if err := lr.cleanupExpiredLogs(); err != nil {
		log.Printf("Failed to enforce periodic log retention: %v", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := lr.cleanupExpiredLogs(); err != nil {
				log.Printf("Failed to enforce periodic log retention: %v", err)
			}
		}
	}
}

func directoryBytes(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total, nil
}

func (lr *LogReceiver) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (lr *LogReceiver) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	if err := lr.logsDirWritable(); err != nil {
		log.Printf("Logs directory is not writable: %v", err)
		http.Error(w, "logs directory is not writable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// logsDirWritable probes the logs directory with a temporary file. The result
// is cached briefly because the endpoint is unauthenticated.
func (lr *LogReceiver) logsDirWritable() error {
	logsDir, _, _, _, _, nowFunc := lr.limits()
	now := nowFunc()
	lr.readyMu.Lock()
	defer lr.readyMu.Unlock()
	if !lr.readyChecked.IsZero() && now.Sub(lr.readyChecked) < readinessCacheInterval {
		return lr.readyErr
	}
	lr.readyChecked = now
	lr.readyErr = checkDirWritable(logsDir)
	return lr.readyErr
}

func checkDirWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".readyz-*")
	if err != nil {
		return err
	}
	return errors.Join(f.Close(), os.Remove(f.Name()))
}

func main() {
	if err := run(); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run() error {
	tokens, err := loadTenantTokens(os.Getenv("AI_LOG_TOKENS"))
	if err != nil {
		return err
	}

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8082"
	}

	maxRequestBytes, err := positiveInt64Env("MAX_REQUEST_BYTES", defaultMaxRequestBytes)
	if err != nil {
		return err
	}
	maxTenantBytes, err := positiveInt64Env("MAX_TENANT_BYTES", defaultMaxTenantBytes)
	if err != nil {
		return err
	}
	requestsPerMinute, err := positiveInt64Env("REQUESTS_PER_MINUTE", defaultRequestsPerMinute)
	if err != nil {
		return err
	}
	retention, err := positiveDurationEnv("RETENTION", defaultLogRetention)
	if err != nil {
		return err
	}
	receiver := newLogReceiver(tokens, getLogsDir(), maxRequestBytes, maxTenantBytes, int(requestsPerMinute), retention)
	if err := receiver.logsDirWritable(); err != nil {
		log.Printf("WARNING: logs directory is not writable, /readyz will fail: %v", err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	go receiver.runRetention(runCtx, retentionSweepInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", receiver.handleHealthz)
	mux.HandleFunc("/readyz", receiver.handleReadyz)
	mux.HandleFunc("/logs", receiver.handleLogs)

	addr := net.JoinHostPort("0.0.0.0", port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	log.Printf("AI Logs Receiver listening on %s", addr)
	serverErrors := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	var runtimeErr error
	select {
	case <-signals:
	case err := <-serverErrors:
		log.Printf("ERROR: server failed: %v", err)
		runtimeErr = err
	}
	cancelRun()
	ctx, cancel := context.WithTimeout(context.Background(), logReceiverShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("ERROR: graceful shutdown: %v", err)
		if runtimeErr == nil {
			runtimeErr = err
		}
	}
	return runtimeErr
}

func positiveInt64Env(name string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func positiveDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return value, nil
}
