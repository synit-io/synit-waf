package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ErrorLog is for application-level errors, warnings, and debug messages.
var ErrorLog = logrus.New()

// rotatingFile appends to a log file whose path may contain date and time
// placeholders. The path is resolved again at most once per second, and the
// file is reopened when the resolved path changes, for example at midnight
// for a "%yyyy-%MM-%dd" pattern.
type rotatingFile struct {
	mu        sync.Mutex
	pattern   string
	path      string
	file      *os.File
	nextCheck time.Time
	now       func() time.Time
}

func openRotatingFile(pattern string) (*rotatingFile, error) {
	rf := &rotatingFile{pattern: pattern, now: time.Now}
	if err := rf.rotateLocked(rf.now()); err != nil {
		return nil, err
	}
	return rf, nil
}

func (rf *rotatingFile) rotateLocked(now time.Time) error {
	rf.nextCheck = now.Truncate(time.Second).Add(time.Second)
	path := resolvePathPattern(rf.pattern, now)
	if rf.file != nil && path == rf.path {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", path, err)
	}
	if rf.file != nil {
		_ = rf.file.Close()
	}
	rf.file = file
	rf.path = path
	return nil
}

func (rf *rotatingFile) Write(p []byte) (int, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.file == nil {
		return 0, os.ErrClosed
	}
	if strings.Contains(rf.pattern, "%") {
		if now := rf.now(); !now.Before(rf.nextCheck) {
			// Keep writing to the current file when the next one cannot be opened.
			_ = rf.rotateLocked(now)
		}
	}
	return rf.file.Write(p)
}

func (rf *rotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.file == nil {
		return nil
	}
	err := rf.file.Close()
	rf.file = nil
	return err
}

// fileLogHook is a Logrus hook that writes log entries to a file with a specific formatter.
type fileLogHook struct {
	file      *rotatingFile
	formatter logrus.Formatter
}

func (h *fileLogHook) Close() error {
	return h.file.Close()
}

// CustomTextFormatter is a custom Logrus formatter to change log level text.
type CustomTextFormatter struct {
	logrus.TextFormatter
}

// Format formats the log entry.
func (f *CustomTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// Get the default formatted log entry
	b, err := f.TextFormatter.Format(entry)
	if err != nil {
		return b, err
	}

	// Replace the level text for error level
	if entry.Level == logrus.ErrorLevel {
		b = bytes.Replace(b, []byte("level=error"), []byte("level=ERROR"), 1)
	}

	return b, nil
}

// newFileLogHook creates a new hook for file logging.
func newFileLogHook(path string, format string) (*fileLogHook, error) {
	var formatter logrus.Formatter
	switch strings.ToLower(format) {
	case "json":
		formatter = &logrus.JSONFormatter{}
	case "text":
		formatter = &logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		}
	default:
		return nil, fmt.Errorf("invalid log format: %s", format)
	}

	file, err := openRotatingFile(path)
	if err != nil {
		return nil, err
	}
	return &fileLogHook{file: file, formatter: formatter}, nil
}

// Fire is called by Logrus for each log entry.
func (h *fileLogHook) Fire(entry *logrus.Entry) error {
	line, err := h.formatter.Format(entry)
	if err != nil {
		return err
	}
	_, err = h.file.Write(line)
	return err
}

// Levels returns the log levels that this hook will fire for.
func (h *fileLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// webhookLogHook sends log entries to a remote webhook URL.
type webhookLogHook struct {
	url             string
	token           string
	client          *http.Client
	queue           chan []byte
	workers         sync.WaitGroup
	mu              sync.RWMutex
	closed          bool
	dropped         atomic.Uint64
	ctx             context.Context
	cancel          context.CancelFunc
	shutdownTimeout time.Duration
}

const (
	maxForwardedLogPayloadBytes = 16 << 10
	maxForwardedBatchEntries    = 100
	maxForwardedBatchBytes      = 512 << 10
	logForwarderFlushInterval   = 250 * time.Millisecond
	logForwarderShutdownTimeout = 2 * time.Second
)

func newWebhookLogHook(url, token string, queueSize, workerCount int, timeout time.Duration) *webhookLogHook {
	if queueSize <= 0 {
		queueSize = 1024
	}
	if workerCount <= 0 {
		workerCount = 2
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	hook := &webhookLogHook{
		url:             url,
		token:           token,
		client:          &http.Client{Timeout: timeout},
		queue:           make(chan []byte, queueSize),
		ctx:             ctx,
		cancel:          cancel,
		shutdownTimeout: logForwarderShutdownTimeout,
	}
	for range workerCount {
		hook.workers.Add(1)
		go hook.runWorker()
	}
	return hook
}

// runWorker forwards log events in NDJSON batches. A batch is sent when it
// is full, when the flush interval ends, or when the queue closes.
func (h *webhookLogHook) runWorker() {
	defer h.workers.Done()
	var batch bytes.Buffer
	entries := 0
	flush := func() {
		if entries == 0 {
			return
		}
		h.send(batch.Bytes(), entries)
		batch.Reset()
		entries = 0
	}
	timer := time.NewTimer(logForwarderFlushInterval)
	defer timer.Stop()
	timerActive := false

	for {
		var timerC <-chan time.Time
		if timerActive {
			timerC = timer.C
		}
		select {
		case payload, ok := <-h.queue:
			if !ok {
				flush()
				return
			}
			if entries > 0 {
				batch.WriteByte('\n')
			}
			batch.Write(payload)
			entries++
			if entries >= maxForwardedBatchEntries || batch.Len() >= maxForwardedBatchBytes {
				flush()
				timerActive = false
			} else if !timerActive {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(logForwarderFlushInterval)
				timerActive = true
			}
		case <-timerC:
			timerActive = false
			flush()
		}
	}
}

func (h *webhookLogHook) send(body []byte, entries int) {
	if h.ctx.Err() != nil {
		h.recordDrops(entries)
		return
	}
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		h.recordDrops(entries)
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.recordDrops(entries)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		h.recordDrops(entries)
	}
}

func (h *webhookLogHook) recordDrops(entries int) {
	for range entries {
		h.recordDrop()
	}
}

func (h *webhookLogHook) recordDrop() {
	h.dropped.Add(1)
	logForwardDroppedTotal.Inc()
}

func (h *webhookLogHook) Fire(entry *logrus.Entry) error {
	// Create a copy of data and add level/time
	data := make(map[string]any, len(entry.Data)+3)
	maps.Copy(data, entry.Data)
	data["level"] = entry.Level.String()
	data["timestamp"] = entry.Time.Format(time.RFC3339)
	data["message"] = entry.Message

	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	h.enqueue(payload)
	return nil
}

// enqueue hands one JSON event to the workers without blocking the caller.
func (h *webhookLogHook) enqueue(payload []byte) {
	if len(payload) > maxForwardedLogPayloadBytes {
		h.recordDrop()
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return
	}
	select {
	case h.queue <- payload:
	default:
		h.recordDrop()
	}
}

func (h *webhookLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *webhookLogHook) Close() error {
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		close(h.queue)
	}
	h.mu.Unlock()
	done := make(chan struct{})
	go func() {
		h.workers.Wait()
		close(done)
	}()
	timer := time.NewTimer(h.shutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		h.cancel()
		<-done
	}
	h.cancel()
	return nil
}

var (
	loggingClosersMu sync.Mutex
	loggingClosers   []io.Closer
)

func registerLoggingCloser(closer io.Closer) {
	loggingClosersMu.Lock()
	loggingClosers = append(loggingClosers, closer)
	loggingClosersMu.Unlock()
}

// CloseLogging flushes and closes active file and webhook hooks.
func CloseLogging() error {
	loggingClosersMu.Lock()
	closers := loggingClosers
	loggingClosers = nil
	loggingClosersMu.Unlock()
	var errs []error
	for _, closer := range closers {
		errs = append(errs, closer.Close())
	}
	return errors.Join(errs...)
}

// accessLogRecord is one access log line.
type accessLogRecord struct {
	clientIP  string
	method    string
	host      string
	path      string
	proto     string
	status    int
	size      int64
	duration  time.Duration
	referer   string
	userAgent string
	tenant    string
	user      string
}

// accessLogSinks holds the prepared access log outputs. Handlers are built
// once in SetupLogging, so a request only fills a fixed attribute list.
type accessLogSinks struct {
	console *slog.Logger
	file    *slog.Logger
	forward *webhookLogHook
}

var accessLog atomic.Pointer[accessLogSinks]

func init() {
	accessLog.Store(&accessLogSinks{console: newAccessLogger(os.Stdout, "text")})
}

// newAccessLogger keeps the level lower case, as the previous formatter wrote it.
func newAccessLogger(w io.Writer, format string) *slog.Logger {
	options := &slog.HandlerOptions{ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
		if attr.Key == slog.LevelKey {
			attr.Value = slog.StringValue(strings.ToLower(attr.Value.String()))
		}
		return attr
	}}
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(w, options))
	}
	return slog.New(slog.NewTextHandler(w, options))
}

// SetAccessLogOutput redirects the console access log. Tests use it.
func SetAccessLogOutput(w io.Writer) {
	current := accessLog.Load()
	accessLog.Store(&accessLogSinks{console: newAccessLogger(w, "text"), file: current.file, forward: current.forward})
}

func writeAccessLog(record accessLogRecord) {
	sinks := accessLog.Load()
	attrs := [12]slog.Attr{
		slog.String("client_ip", boundedLogValue(record.clientIP)),
		slog.String("method", record.method),
		slog.String("host", boundedLogValue(record.host)),
		slog.String("path", boundedLogValue(record.path)),
		slog.String("proto", record.proto),
		slog.Int("status", record.status),
		slog.Int64("size_bytes", record.size),
		slog.Int64("duration_ms", record.duration.Milliseconds()),
		slog.String("referer", boundedLogValue(record.referer)),
		slog.String("user_agent", boundedLogValue(record.userAgent)),
		slog.String("tenant", record.tenant),
	}
	used := 11
	if record.user != "" {
		attrs[used] = slog.String("user", record.user)
		used++
	}
	ctx := context.Background()
	sinks.console.LogAttrs(ctx, slog.LevelInfo, "request handled", attrs[:used]...)
	if sinks.file != nil {
		sinks.file.LogAttrs(ctx, slog.LevelInfo, "request handled", attrs[:used]...)
	}
	if sinks.forward != nil {
		payload, err := json.Marshal(struct {
			ClientIP   string `json:"client_ip"`
			Method     string `json:"method"`
			Host       string `json:"host"`
			Path       string `json:"path"`
			Proto      string `json:"proto"`
			Status     int    `json:"status"`
			SizeBytes  int64  `json:"size_bytes"`
			DurationMS int64  `json:"duration_ms"`
			Referer    string `json:"referer"`
			UserAgent  string `json:"user_agent"`
			Tenant     string `json:"tenant"`
			User       string `json:"user,omitempty"`
			Level      string `json:"level"`
			Timestamp  string `json:"timestamp"`
			Message    string `json:"message"`
		}{
			ClientIP: boundedLogValue(record.clientIP), Method: record.method, Host: boundedLogValue(record.host),
			Path: boundedLogValue(record.path), Proto: record.proto, Status: record.status, SizeBytes: record.size,
			DurationMS: record.duration.Milliseconds(), Referer: boundedLogValue(record.referer),
			UserAgent: boundedLogValue(record.userAgent), Tenant: record.tenant, User: record.user,
			Level: "info", Timestamp: time.Now().Format(time.RFC3339), Message: "request handled",
		})
		if err == nil {
			sinks.forward.enqueue(payload)
		}
	}
}

// stderrIsTerminal reports whether colored console output is appropriate.
func stderrIsTerminal() bool {
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// SetupLogging configures the global loggers based on the application configuration.
func SetupLogging(cfg AppConfig) error {
	_ = CloseLogging()
	ErrorLog.ReplaceHooks(make(logrus.LevelHooks))
	// --- Configure Error Logger ---
	ErrorLog.SetOutput(os.Stderr)
	level, err := logrus.ParseLevel(cfg.GlobalSettings.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
		ErrorLog.Warnf("Invalid log level '%s', defaulting to 'INFO'", cfg.GlobalSettings.LogLevel)
	}
	ErrorLog.SetLevel(level)
	// Colors only help on a terminal; container log collectors store the
	// escape sequences verbatim.
	ErrorLog.SetFormatter(&CustomTextFormatter{
		FullTimestamp: true,
		ForceColors:   stderrIsTerminal(),
		DisableColors: !stderrIsTerminal(),
	})

	if cfg.Logging.ErrorLog.Enabled {
		hook, err := newFileLogHook(cfg.Logging.ErrorLog.Path, cfg.Logging.ErrorLog.Format)
		if err != nil {
			return fmt.Errorf("initialize error log file hook: %w", err)
		}
		ErrorLog.AddHook(hook)
		registerLoggingCloser(hook)
		ErrorLog.Infof("Error logs will also be written to %s in %s format", cfg.Logging.ErrorLog.Path, cfg.Logging.ErrorLog.Format)
	}

	// --- Configure Access Logger ---
	sinks := &accessLogSinks{console: newAccessLogger(os.Stdout, "text")}
	if cfg.Logging.AccessLog.Enabled {
		file, err := openRotatingFile(cfg.Logging.AccessLog.Path)
		if err != nil {
			_ = CloseLogging()
			return fmt.Errorf("initialize access log file: %w", err)
		}
		format := strings.ToLower(cfg.Logging.AccessLog.Format)
		if format != "json" && format != "text" {
			_ = file.Close()
			_ = CloseLogging()
			return fmt.Errorf("initialize access log file: invalid log format: %s", cfg.Logging.AccessLog.Format)
		}
		sinks.file = newAccessLogger(file, format)
		registerLoggingCloser(file)
		ErrorLog.Infof("Access logs will also be written to %s in %s format", cfg.Logging.AccessLog.Path, cfg.Logging.AccessLog.Format)
	}

	// --- Configure Log Forwarder (for AI Analyst) ---
	if cfg.Logging.LogForwarder.Enabled {
		forwarder := newWebhookLogHook(cfg.Logging.LogForwarder.URL, cfg.Logging.LogForwarder.Token, 1024, 2, 2*time.Second)
		ErrorLog.AddHook(forwarder)
		sinks.forward = forwarder
		registerLoggingCloser(forwarder)
		ErrorLog.Infof("AI Analyst Log Forwarder enabled (URL: %s)", cfg.Logging.LogForwarder.URL)
	}
	accessLog.Store(sinks)
	return nil
}

// resolvePathPattern replaces date/time placeholders in a log file path.
func resolvePathPattern(path string, now time.Time) string {
	if !strings.Contains(path, "%") {
		return path
	}
	r := strings.NewReplacer(
		"%yyyy", now.Format("2006"),
		"%yy", now.Format("06"),
		"%MM", now.Format("01"),
		"%M", now.Format("Jan"),
		"%dd", now.Format("02"),
		"%d", now.Format("2"),
		"%HH", now.Format("15"),
		"%hh", now.Format("03"),
		"%mm", now.Format("04"),
		"%ss", now.Format("05"),
	)
	return r.Replace(path)
}
