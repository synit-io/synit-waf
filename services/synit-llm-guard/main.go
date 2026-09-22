package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/knights-analytics/hugot"
	"github.com/knights-analytics/hugot/pipelines"
)

// DetectRequest matches the WAF sidecar API request structure.
type DetectRequest struct {
	Tenant       string   `json:"tenant"`
	Path         string   `json:"path"`
	Texts        []string `json:"texts"`
	MaxLatencyMS int64    `json:"max_latency_ms"`
}

// DetectResponse matches the WAF sidecar API response structure.
type DetectResponse struct {
	Verdict string    `json:"verdict"`
	Score   float64   `json:"score"`
	Scores  []float64 `json:"scores"`
	Model   string    `json:"model"`
	Reason  string    `json:"reason"`
}

type textClassifier interface {
	Classify(context.Context, []string) ([]float64, error)
	Close() error
}

// closeWaitTimeout bounds how long Close waits for an inference that is still running.
const closeWaitTimeout = 10 * time.Second

type hugotClassifier struct {
	// runPipeline and destroy are the hugot pipeline run and session teardown. They are
	// fields so the slot handling and label mapping can be tested without loading a model.
	runPipeline     func(context.Context, []string) (*pipelines.TextClassificationOutput, error)
	destroy         func() error
	injectionLabels map[string]bool
	safeLabels      map[string]bool
	slot            chan struct{}
}

type inferenceResult struct {
	scores []float64
	err    error
}

func newHugotClassifier(ctx context.Context, modelPath string, injectionLabels, safeLabels map[string]bool) (*hugotClassifier, error) {
	session, err := hugot.NewGoSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("create inference session: %w", err)
	}
	pipeline, err := hugot.NewPipeline(session, hugot.TextClassificationConfig{
		ModelPath: modelPath,
		Name:      "prompt-injection",
		Options:   []hugot.TextClassificationOption{pipelines.WithSoftmax(), pipelines.WithSingleLabel()},
	})
	if err != nil {
		_ = session.Destroy()
		return nil, fmt.Errorf("load text-classification model: %w", err)
	}
	if err := validateModelLabels(pipeline.GetModel().IDLabelMap, injectionLabels, safeLabels); err != nil {
		_ = session.Destroy()
		return nil, err
	}
	return &hugotClassifier{
		runPipeline:     pipeline.RunPipeline,
		destroy:         session.Destroy,
		injectionLabels: injectionLabels,
		safeLabels:      safeLabels,
		slot:            make(chan struct{}, 1),
	}, nil
}

func validateModelLabels(labels map[int]string, injectionLabels, safeLabels map[string]bool) error {
	if len(labels) != 2 {
		return fmt.Errorf("prompt-injection model must expose exactly two labels")
	}
	injectionCount := 0
	safeCount := 0
	for _, rawLabel := range labels {
		label := strings.ToUpper(strings.TrimSpace(rawLabel))
		if injectionLabels[label] == safeLabels[label] {
			return fmt.Errorf("model label %q must belong to exactly one configured label set", rawLabel)
		}
		if injectionLabels[label] {
			injectionCount++
		} else {
			safeCount++
		}
	}
	if injectionCount != 1 || safeCount != 1 {
		return fmt.Errorf("prompt-injection model must expose exactly one injection and one safe label")
	}
	return nil
}

func (c *hugotClassifier) Classify(ctx context.Context, texts []string) ([]float64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c.slot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// The inference goroutine owns the slot from here on and releases it only when the
	// model run has really ended. A caller that times out gets its error right away, but
	// the next inference still waits for this one. A goroutine is started only by a caller
	// that holds the slot, so timed-out callers can leave at most cap(slot) of them behind.
	done := make(chan inferenceResult, 1)
	go func() {
		defer func() { <-c.slot }()
		scores, err := c.infer(texts)
		done <- inferenceResult{scores: scores, err: err}
	}()
	select {
	case result := <-done:
		return result.scores, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// infer runs one model inference to completion. It deliberately takes no caller context:
// on cancellation hugot returns while its model execution keeps running and frees the
// input tensors under it, so the run must never be cancelled from outside.
func (c *hugotClassifier) infer(texts []string) (scores []float64, err error) {
	defer func() {
		// This runs outside the HTTP handler goroutine, so net/http does not recover it.
		if r := recover(); r != nil {
			scores, err = nil, fmt.Errorf("inference panicked: %v", r)
		}
	}()
	result, err := c.runPipeline(context.Background(), texts)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("model returned no result")
	}
	if len(result.ClassificationOutputs) != len(texts) {
		return nil, fmt.Errorf("model returned %d outputs for %d texts", len(result.ClassificationOutputs), len(texts))
	}
	scores = make([]float64, len(texts))
	for i, outputs := range result.ClassificationOutputs {
		if len(outputs) != 1 {
			return nil, fmt.Errorf("model output %d contains %d labels; expected one", i, len(outputs))
		}
		label := strings.ToUpper(strings.TrimSpace(outputs[0].Label))
		score := float64(outputs[0].Score)
		switch {
		case c.injectionLabels[label]:
			scores[i] = score
		case c.safeLabels[label]:
			scores[i] = 1 - score
		default:
			return nil, fmt.Errorf("model returned unknown label %q", outputs[0].Label)
		}
	}
	return scores, nil
}

func (c *hugotClassifier) Close() error {
	// An inference abandoned by a timed-out caller may still be running. Destroying the
	// session under it is unsafe, so take the slot first and keep it.
	timer := time.NewTimer(closeWaitTimeout)
	defer timer.Stop()
	select {
	case c.slot <- struct{}{}:
	case <-timer.C:
		return errors.New("inference still running; session not destroyed")
	}
	return c.destroy()
}

type guardServer struct {
	classifier       textClassifier
	modelName        string
	authToken        string
	threshold        float64
	maxRequestBytes  int64
	maxTexts         int
	maxTextBytes     int
	chunkBytes       int
	chunkOverlap     int
	maxInferenceTime time.Duration
	admission        chan struct{}
}

func (s *guardServer) handleDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auth := r.Header.Get("Authorization")
	candidate, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(candidate), []byte(s.authToken)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > s.maxRequestBytes {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request DetectRequest
	if err := decoder.Decode(&request); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if request.Tenant == "" || request.Path == "" || request.MaxLatencyMS < 0 || len(request.Texts) == 0 {
		http.Error(w, "Invalid detection request", http.StatusBadRequest)
		return
	}
	// The WAF treats 400/413/422 as uninspectable input; the body text names the limit.
	if len(request.Texts) > s.maxTexts {
		http.Error(w, fmt.Sprintf("too many texts: %d exceeds the limit of %d", len(request.Texts), s.maxTexts), http.StatusBadRequest)
		return
	}
	for i, text := range request.Texts {
		if text == "" {
			http.Error(w, "Detection text must not be empty", http.StatusBadRequest)
			return
		}
		if len(text) > s.maxTextBytes {
			http.Error(w, fmt.Sprintf("text too large: text %d has %d bytes, the limit is %d", i, len(text), s.maxTextBytes), http.StatusRequestEntityTooLarge)
			return
		}
	}

	// Admission comes after the body is read and validated, so a slow client cannot hold
	// an inference slot while it trickles its request in.
	if s.admission != nil {
		select {
		case s.admission <- struct{}{}:
			defer func() { <-s.admission }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Inference capacity exhausted", http.StatusServiceUnavailable)
			return
		}
	}

	// The tokenizer silently truncates at the model's token window, so longer texts are
	// scored as overlapping chunks. owners maps every chunk back to its input text.
	var chunks []string
	var owners []int
	for i, text := range request.Texts {
		for _, chunk := range splitChunks(text, s.chunkBytes, s.chunkOverlap) {
			chunks = append(chunks, chunk)
			owners = append(owners, i)
		}
	}

	timeout := s.maxInferenceTime
	if request.MaxLatencyMS > 0 && request.MaxLatencyMS < timeout.Milliseconds() {
		timeout = time.Duration(request.MaxLatencyMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	// One model run never sees more than maxTexts sequences, as before chunking. Each
	// text keeps the highest score of its chunks.
	scores := make([]float64, len(request.Texts))
	for start := 0; start < len(chunks); start += s.maxTexts {
		end := min(start+s.maxTexts, len(chunks))
		batchScores, err := s.classifier.Classify(ctx, chunks[start:end])
		if err != nil {
			log.Printf("classification failed: %v", err)
			if errors.Is(err, context.DeadlineExceeded) {
				http.Error(w, "Inference timed out", http.StatusGatewayTimeout)
				return
			}
			http.Error(w, "Inference failed", http.StatusServiceUnavailable)
			return
		}
		if len(batchScores) != end-start {
			http.Error(w, "Invalid inference result", http.StatusServiceUnavailable)
			return
		}
		for j, score := range batchScores {
			if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
				http.Error(w, "Invalid inference result", http.StatusServiceUnavailable)
				return
			}
			if owner := owners[start+j]; score > scores[owner] {
				scores[owner] = score
			}
		}
	}
	maxScore := 0.0
	for _, score := range scores {
		if score > maxScore {
			maxScore = score
		}
	}
	// verdict is advisory and uses this service's threshold. The WAF applies its own
	// threshold to scores.
	verdict := "safe"
	if maxScore >= s.threshold {
		verdict = "injection"
	}
	response := DetectResponse{
		Verdict: verdict,
		Score:   maxScore,
		Scores:  scores,
		Model:   s.modelName,
		Reason:  "text_classification",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// splitChunks cuts text into chunks of at most chunkBytes bytes. Consecutive chunks share
// at least overlapBytes bytes, so anything up to that size that straddles a cut is still
// seen whole by one chunk. Cuts are moved back to a UTF-8 rune boundary. Only an overlap
// within a few bytes of the chunk size can force a smaller overlap to keep advancing.
func splitChunks(text string, chunkBytes, overlapBytes int) []string {
	if chunkBytes <= 0 || len(text) <= chunkBytes {
		return []string{text}
	}
	var chunks []string
	start := 0
	for len(text)-start > chunkBytes {
		end := runeBoundary(text, start+chunkBytes)
		if end <= start {
			end = start + chunkBytes
		}
		chunks = append(chunks, text[start:end])
		next := runeBoundary(text, end-overlapBytes)
		if next <= start {
			// The overlap reaches back to the chunk start; step one rune to make progress.
			_, size := utf8.DecodeRuneInString(text[start:])
			next = min(start+size, end)
		}
		start = next
	}
	return append(chunks, text[start:])
}

// runeBoundary moves index back to the start of the rune it points into. Invalid UTF-8
// has no boundary within reach; the index is then returned unchanged.
func runeBoundary(text string, index int) int {
	for i := index; i > 0 && i > index-utf8.UTFMax; i-- {
		if utf8.RuneStart(text[i]) {
			return i
		}
	}
	return index
}

func (s *guardServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func main() {
	if err := run(); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

type guardConfig struct {
	modelPath             string
	modelName             string
	authToken             string
	port                  string
	injectionLabels       map[string]bool
	safeLabels            map[string]bool
	threshold             float64
	maxRequestBytes       int64
	maxTexts              int
	maxTextBytes          int
	chunkBytes            int
	chunkOverlap          int
	maxInferenceTime      time.Duration
	maxConcurrentRequests int
}

func loadConfig() (guardConfig, error) {
	cfg := guardConfig{
		modelPath:       strings.TrimSpace(os.Getenv("MODEL_PATH")),
		modelName:       strings.TrimSpace(os.Getenv("MODEL_NAME")),
		authToken:       strings.TrimSpace(os.Getenv("AUTH_TOKEN")),
		port:            envString("PORT", "5001"),
		injectionLabels: parseLabelSet(envString("INJECTION_LABELS", "INJECTION,LABEL_1,MALICIOUS")),
		safeLabels:      parseLabelSet(envString("SAFE_LABELS", "SAFE,LABEL_0,BENIGN")),
	}
	if cfg.modelPath == "" {
		return guardConfig{}, errors.New("MODEL_PATH is required")
	}
	if cfg.modelName == "" {
		cfg.modelName = filepath.Base(cfg.modelPath)
	}
	if cfg.authToken == "" {
		return guardConfig{}, errors.New("AUTH_TOKEN is required")
	}

	var err error
	if cfg.threshold, err = envFloat("INJECTION_THRESHOLD", 0.5); err != nil {
		return guardConfig{}, err
	}
	if cfg.maxRequestBytes, err = envInt64("MAX_REQUEST_BYTES", 1<<20); err != nil {
		return guardConfig{}, err
	}
	if cfg.maxInferenceTime, err = envDuration("MAX_INFERENCE_TIMEOUT", 10*time.Second); err != nil {
		return guardConfig{}, err
	}
	for _, limit := range []struct {
		name     string
		fallback int64
		target   *int
	}{
		{"MAX_TEXTS", 32, &cfg.maxTexts},
		{"MAX_TEXT_BYTES", 8192, &cfg.maxTextBytes},
		{"CHUNK_BYTES", 510, &cfg.chunkBytes},
		{"CHUNK_OVERLAP_BYTES", 64, &cfg.chunkOverlap},
		{"MAX_CONCURRENT_REQUESTS", 8, &cfg.maxConcurrentRequests},
	} {
		value, err := envInt64(limit.name, limit.fallback)
		if err != nil {
			return guardConfig{}, err
		}
		*limit.target = int(value)
	}
	if math.IsNaN(cfg.threshold) || math.IsInf(cfg.threshold, 0) || cfg.threshold <= 0 || cfg.threshold >= 1 || cfg.maxRequestBytes <= 0 || cfg.maxTexts <= 0 || cfg.maxTextBytes <= 0 || cfg.maxInferenceTime <= 0 || cfg.maxConcurrentRequests <= 0 {
		return guardConfig{}, errors.New("inference limits must be positive and INJECTION_THRESHOLD must be between 0 and 1")
	}
	if cfg.chunkBytes <= 0 || cfg.chunkOverlap <= 0 || cfg.chunkOverlap >= cfg.chunkBytes {
		return guardConfig{}, errors.New("CHUNK_BYTES and CHUNK_OVERLAP_BYTES must be positive and CHUNK_OVERLAP_BYTES must be smaller than CHUNK_BYTES")
	}
	return cfg, nil
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	classifier, err := newHugotClassifier(context.Background(), cfg.modelPath, cfg.injectionLabels, cfg.safeLabels)
	if err != nil {
		return fmt.Errorf("initialize classifier: %w", err)
	}
	defer func() {
		if err := classifier.Close(); err != nil {
			log.Printf("close classifier: %v", err)
		}
	}()

	guard := &guardServer{
		classifier:       classifier,
		modelName:        cfg.modelName,
		authToken:        cfg.authToken,
		threshold:        cfg.threshold,
		maxRequestBytes:  cfg.maxRequestBytes,
		maxTexts:         cfg.maxTexts,
		maxTextBytes:     cfg.maxTextBytes,
		chunkBytes:       cfg.chunkBytes,
		chunkOverlap:     cfg.chunkOverlap,
		maxInferenceTime: cfg.maxInferenceTime,
		admission:        make(chan struct{}, cfg.maxConcurrentRequests),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/detect", guard.handleDetect)
	mux.HandleFunc("/livez", guard.handleHealth)
	mux.HandleFunc("/readyz", guard.handleHealth)
	mux.HandleFunc("/health", guard.handleHealth)

	// The write deadline starts once the headers are read, so it has to cover the body
	// read and the inference deadline or a slow inference loses its response.
	const readTimeout = 15 * time.Second
	server := &http.Server{
		Addr:              net.JoinHostPort("0.0.0.0", cfg.port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      readTimeout + cfg.maxInferenceTime + 5*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("synit-llm-guard listening on %s with model %s", server.Addr, cfg.modelName)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	var runtimeErr error
	select {
	case <-signals:
	case err := <-serverErrors:
		log.Printf("server failed: %v", err)
		runtimeErr = err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown: %v", err)
		if runtimeErr == nil {
			runtimeErr = err
		}
	}
	return runtimeErr
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt64(name string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func envFloat(name string, fallback float64) (float64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func parseLabelSet(raw string) map[string]bool {
	labels := make(map[string]bool)
	for label := range strings.SplitSeq(raw, ",") {
		label = strings.ToUpper(strings.TrimSpace(label))
		if label != "" {
			labels[label] = true
		}
	}
	return labels
}
