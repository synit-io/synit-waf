package waf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// llmProtectionDetectionRules are the built-in static prompt-injection rules.
// The patterns target instruction-override and prompt-extraction phrasing.
// Generic role play ("act as a translator") is deliberately not matched: it is
// one of the most common legitimate prompts.
const llmProtectionDetectionRules = `
# Instruction override and known jailbreak personas
SecRule ARGS|REQUEST_BODY "@rx (?i)(?:(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules|directions|context)|\bdan\s+mode\b|\bdo\s+anything\s+now\b|\bjailbreak\s+(?:mode|prompt)\b|you\s+are\s+now\s+(?:in\s+)?(?:dan|developer|jailbreak|unrestricted|god)\s+mode)" \
    "id:440012,phase:2,deny,status:403,log,msg:'Potential classic prompt injection pattern matched'"

# System prompt extraction attempts
SecRule ARGS|REQUEST_BODY "@rx (?i)(?:(?:repeat|reveal|print|show|output|leak)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+|initial\s+|hidden\s+|original\s+)?(?:prompt|instructions)|what\s+(?:is|are)\s+your\s+system\s+(?:prompt|instructions))" \
    "id:440013,phase:2,deny,status:403,log,msg:'Potential system prompt extraction attempt matched'"
`

// buildLLMProtectionRules returns the built-in llm-protection rule set. The
// detection rules only run for requests under inspectPaths, so they do not
// fire on unrelated endpoints of the same tenant. With no paths the rules
// apply to every request.
func buildLLMProtectionRules(inspectPaths []string) string {
	var rules strings.Builder
	rules.WriteString(`
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "(?i)application/json" \
    "id:440010,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
`)
	if len(inspectPaths) > 0 {
		alternatives := make([]string, 0, len(inspectPaths))
		for _, path := range inspectPaths {
			alternatives = append(alternatives, regexp.QuoteMeta(strings.TrimSuffix(path, "/")))
		}
		fmt.Fprintf(&rules, `
SecRule REQUEST_FILENAME "!@rx ^(?:%s)(?:/|$)" \
    "id:440011,phase:2,pass,nolog,t:none,t:normalizePath,skipAfter:SYNIT-LLM-END"
`, strings.Join(alternatives, "|"))
	}
	rules.WriteString(llmProtectionDetectionRules)
	rules.WriteString("SecMarker \"SYNIT-LLM-END\"\n")
	return rules.String()
}

// defaultLLMProtectionRules is the built-in rule set without path scoping.
var defaultLLMProtectionRules = buildLLMProtectionRules(nil)

// DetectRequest is the payload sent to the sidecar service.
type DetectRequest struct {
	Tenant       string   `json:"tenant"`
	Path         string   `json:"path"`
	Texts        []string `json:"texts"`
	MaxLatencyMS int64    `json:"max_latency_ms"`
}

// DetectResponse is the response structure from the sidecar service.
type DetectResponse struct {
	Verdict string    `json:"verdict"`
	Score   float64   `json:"score"`
	Scores  []float64 `json:"scores"`
	Model   string    `json:"model"`
	Reason  string    `json:"reason"`
}

const (
	defaultLLMSidecarTimeout  = 500 * time.Millisecond
	defaultLLMMaxTextBytes    = 8192
	defaultLLMSidecarMaxBatch = 32
	llmTextChunkOverlapBytes  = 256
)

// errSidecarRejectedInput means the sidecar refused the texts themselves, for
// example because a text is too large. That is a property of the request, not
// a dependency failure, so fail_mode does not apply.
var errSidecarRejectedInput = errors.New("sidecar rejected the input")

// SetDefaults normalizes and sets fallback defaults for the LLMProtectionConfig.
func (p *LLMProtectionConfig) SetDefaults() {
	if p.Mode == "" {
		p.Mode = "hybrid"
	}
	if p.Action == "" {
		p.Action = "audit"
	}
	if p.FailMode == "" {
		p.FailMode = "open"
	}
	if p.Threshold == 0.0 {
		p.Threshold = 0.85
	}
	if p.Timeout <= 0 {
		p.Timeout = defaultLLMSidecarTimeout
	}
	if p.MaxTextBytes <= 0 {
		p.MaxTextBytes = defaultLLMMaxTextBytes
	}
	if p.SidecarMaxBatch <= 0 {
		p.SidecarMaxBatch = defaultLLMSidecarMaxBatch
	}
	if p.SidecarURL == "" {
		p.SidecarURL = "http://localhost:5001/v1/detect"
	}
	if len(p.InspectPaths) == 0 {
		p.InspectPaths = []string{"/v1/chat/completions", "/v1/messages"}
	}
	if len(p.InspectJSONFields) == 0 {
		p.InspectJSONFields = []string{"prompt", "input", "query", "messages[].content"}
	}
}

// splitLLMText cuts text into overlapping chunks of at most maxBytes on UTF-8
// boundaries. The overlap keeps a phrase that straddles a cut in one chunk.
func splitLLMText(text string, maxBytes int) []string {
	if maxBytes <= 0 || len(text) <= maxBytes {
		return []string{text}
	}
	overlap := min(llmTextChunkOverlapBytes, maxBytes/4)
	var chunks []string
	for start := 0; start < len(text); {
		end := min(start+maxBytes, len(text))
		for end < len(text) && end > start && !utf8.RuneStart(text[end]) {
			end--
		}
		chunks = append(chunks, text[start:end])
		if end == len(text) {
			break
		}
		next := end - overlap
		for next > start && !utf8.RuneStart(text[next]) {
			next--
		}
		if next <= start {
			next = end
		}
		start = next
	}
	return chunks
}

// applyLLMProtection inspects incoming requests for potential LLM prompt injections.
// It returns true if the request should be blocked.
func (h *ProxyHandler) applyLLMProtection(w http.ResponseWriter, r *http.Request, policy LLMProtectionConfig) bool {
	if !policy.Enabled {
		return false
	}

	// 1. Check Path Match (Prefix match)
	if !pathMatchesAny(policy.InspectPaths, r.URL.Path) {
		return false
	}

	// 2. Read and buffer the body. max_body_bytes bounds the whole request;
	// max_text_bytes bounds one text sent to the sidecar.
	limit := int64(policy.MaxBodyBytes)
	if limit <= 0 {
		limit = h.requestBodyLimit.Load()
	}
	if limit <= 0 {
		limit = defaultRequestBodyCap
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return true
	}
	mediaType = strings.ToLower(mediaType)
	isJSON := mediaType == "application/json"
	isText := mediaType == "text/plain"

	if !isJSON && !isText {
		return false
	}

	if r.Body == nil {
		return false
	}
	if hasUnsupportedContentEncoding(r) {
		http.Error(w, "Compressed LLM request bodies cannot be inspected", http.StatusUnsupportedMediaType)
		return true
	}

	bodyBytes, err := h.inspectionBody(r, limit)
	if errors.Is(err, errInspectionBodyTooLarge) {
		h.rejectInspectionOversize(w, r, "llm_protection")
		return true
	}
	if err != nil {
		ErrorLog.Errorf("llm-protection: failed to read request body: %v", err)
		if policy.FailMode == "closed" {
			http.Error(w, "Security dependency failure", http.StatusForbidden)
			return true
		}
		return false
	}

	// 3. Extract Texts
	var texts []string
	if isJSON {
		if !json.Valid(bodyBytes) {
			http.Error(w, "Invalid JSON request body", http.StatusBadRequest)
			return true
		}
		bodyStr := string(bodyBytes)
		for _, field := range policy.InspectJSONFields {
			// Normalize syntax for gjson: messages[].content -> messages.#.content
			normField := strings.ReplaceAll(field, "[]", ".#")
			res := gjson.Get(bodyStr, normField)
			if !res.Exists() {
				continue
			}
			if res.IsArray() {
				res.ForEach(func(key, value gjson.Result) bool {
					if valStr := value.String(); valStr != "" {
						texts = append(texts, valStr)
					}
					return true
				})
			} else if valStr := res.String(); valStr != "" {
				texts = append(texts, valStr)
			}
		}
	} else {
		texts = append(texts, string(bodyBytes))
	}

	if len(texts) == 0 {
		return false
	}
	tenantMetric := h.metricTenant(r)

	// If mode is "rules" only, we've already run Coraza rules as part of the WAF pipeline (Layer 1).
	if policy.Mode == "rules" {
		return false
	}

	// 4. ML / Hybrid sidecar check. Long texts are scored in chunks so no
	// part of a text escapes the per-text limit of the sidecar.
	var chunks []string
	for _, text := range texts {
		chunks = append(chunks, splitLLMText(text, policy.MaxTextBytes)...)
	}

	highestScore := 0.0
	var textsToQuery []string
	queued := make(map[string]bool)

	for _, text := range chunks {
		hashKey := llmCacheKey(policy.SidecarURL, tenantMetric, r.URL.Path, text)
		if score, ok := h.llmCache.Get(hashKey); ok {
			if score > highestScore {
				highestScore = score
			}
		} else if !queued[hashKey] {
			queued[hashKey] = true
			textsToQuery = append(textsToQuery, text)
		}
	}

	// If we have texts to query, ask the sidecar
	if len(textsToQuery) > 0 {
		scores, err := h.querySidecarBatched(r.Context(), tenantMetric, r.URL.Path, policy, textsToQuery)
		if errors.Is(err, errSidecarRejectedInput) {
			ErrorLog.WithFields(logrus.Fields{"tenant": tenantMetric, "inspect_path": r.URL.Path}).Warnf("llm-protection: %v", err)
			if policy.Action == "audit" {
				auditModeEventsTotal.WithLabelValues(tenantMetric).Inc()
				return false
			}
			blockedTotal.WithLabelValues("llm_protection_uninspectable", tenantMetric).Inc()
			http.Error(w, "LLM request cannot be inspected", http.StatusUnprocessableEntity)
			return true
		}
		if err != nil {
			ErrorLog.Errorf("llm-protection: sidecar query failed: %v", err)
			if policy.FailMode == "closed" {
				http.Error(w, "Security dependency failure", http.StatusForbidden)
				return true
			}
			return false
		}

		// Update cache and keep track of highest score
		for i, text := range textsToQuery {
			score := scores[i]
			hashKey := llmCacheKey(policy.SidecarURL, tenantMetric, r.URL.Path, text)
			h.llmCache.Add(hashKey, score)
			if score > highestScore {
				highestScore = score
			}
		}
	}

	// 5. Evaluate verdict
	if highestScore >= policy.Threshold {
		msg := fmt.Sprintf("Blocked LLM prompt injection (score: %.2f)", highestScore)
		if policy.Action == "audit" {
			auditModeEventsTotal.WithLabelValues(tenantMetric).Inc()
			ErrorLog.WithFields(logrus.Fields{
				"tenant":       tenantMetric,
				"score":        highestScore,
				"action":       "audit",
				"inspect_path": r.URL.Path,
			}).Warn(msg)
			return false
		}

		blockedTotal.WithLabelValues("llm_protection", tenantMetric).Inc()
		ErrorLog.WithFields(logrus.Fields{
			"tenant":       tenantMetric,
			"score":        highestScore,
			"action":       "deny",
			"inspect_path": r.URL.Path,
		}).Error(msg)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		// The only variable part is a formatted float in a JSON body.
		_, _ = fmt.Fprintf(w, `{"error": "Forbidden", "message": "Potential prompt injection detected (score: %.2f)"}`, highestScore) // #nosec G705
		return true
	}

	return false
}

func llmCacheKey(sidecarURL, tenant, path, prompt string) string {
	return hashText(sidecarURL + "\x00" + tenant + "\x00" + path + "\x00" + prompt)
}

func hashText(text string) string {
	h := sha256.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// querySidecarBatched scores texts in batches of at most sidecar_max_batch.
// All batches share one deadline of policy.Timeout.
func (h *ProxyHandler) querySidecarBatched(ctx context.Context, tenant, path string, policy LLMProtectionConfig, texts []string) ([]float64, error) {
	batchSize := policy.SidecarMaxBatch
	if batchSize <= 0 {
		batchSize = defaultLLMSidecarMaxBatch
	}
	reqCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()

	scores := make([]float64, 0, len(texts))
	for start := 0; start < len(texts); start += batchSize {
		end := min(start+batchSize, len(texts))
		batch, err := h.querySidecar(reqCtx, tenant, path, policy, texts[start:end])
		if err != nil {
			return nil, err
		}
		scores = append(scores, batch...)
	}
	return scores, nil
}

func (h *ProxyHandler) querySidecar(ctx context.Context, tenant, path string, policy LLMProtectionConfig, texts []string) ([]float64, error) {
	maxLatency := policy.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		maxLatency = min(maxLatency, time.Until(deadline))
	}
	reqPayload := DetectRequest{
		Tenant:       tenant,
		Path:         path,
		Texts:        texts,
		MaxLatencyMS: max(maxLatency.Milliseconds(), 0),
	}

	jsonData, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", policy.SidecarURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+policy.SidecarToken)

	resp, err := h.sidecarClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: status %d: %s", errSidecarRejectedInput, resp.StatusCode, strings.TrimSpace(string(detail)))
	default:
		return nil, fmt.Errorf("sidecar returned status %d", resp.StatusCode)
	}

	var resPayload DetectResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := decoder.Decode(&resPayload); err != nil {
		return nil, err
	}
	if len(resPayload.Scores) != len(texts) {
		return nil, fmt.Errorf("sidecar returned %d scores for %d texts", len(resPayload.Scores), len(texts))
	}
	for _, score := range resPayload.Scores {
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
			return nil, fmt.Errorf("sidecar returned invalid score %.4f", score)
		}
	}

	return resPayload.Scores, nil
}
