# Synit LLM Guard

Synit LLM Guard is the optional prompt-injection classifier used by Synit WAF `ml` and `hybrid` policies. It loads a Hugging Face-compatible ONNX text-classification model through Hugot's pure-Go backend and returns one injection probability per submitted text.

No model weights are bundled. Select and evaluate a binary classifier for your language, prompt shape, latency budget, and acceptable false-positive rate before enabling deny mode.

## Model directory

`MODEL_PATH` points to a model directory, not only an ONNX file. The directory must contain the Hugging Face export artifacts required by Hugot, including `model.onnx`, `tokenizer.json`, and a `config.json` with exactly two `id2label` entries.

Map those labels explicitly:

```bash
export MODEL_PATH=/absolute/path/to/model
export MODEL_NAME=prompt-injection-v1
export INJECTION_LABELS='INJECTION,LABEL_1,MALICIOUS'
export SAFE_LABELS='SAFE,LABEL_0,BENIGN'
export AUTH_TOKEN='replace-with-a-long-random-token'
go run .
```

Startup fails when the model cannot load, does not expose exactly two labels, or a model label is absent from or appears in both configured label sets.

## Configuration

- `MODEL_PATH`: required model directory.
- `AUTH_TOKEN`: required bearer token shared with the WAF's `sidecar_token` or `sidecar_token_env`.
- `MODEL_NAME`: response label; defaults to the model directory name.
- `INJECTION_LABELS`: comma-separated injection labels; defaults to `INJECTION,LABEL_1,MALICIOUS`.
- `SAFE_LABELS`: comma-separated safe labels; defaults to `SAFE,LABEL_0,BENIGN`.
- `INJECTION_THRESHOLD`: threshold for the advisory `verdict` field only; default `0.5`, exclusive range `(0,1)`. The WAF does not use it.
- `MAX_REQUEST_BYTES`: HTTP request limit; default `1048576`.
- `MAX_TEXTS`: maximum texts per call and maximum sequences per model run; default `32`.
- `MAX_TEXT_BYTES`: maximum bytes per text; default `8192`.
- `CHUNK_BYTES`: maximum bytes per scored chunk; default `510`. See [Long texts](#long-texts).
- `CHUNK_OVERLAP_BYTES`: bytes shared by consecutive chunks; default `64`. Must be positive and smaller than `CHUNK_BYTES`.
- `MAX_INFERENCE_TIMEOUT`: server-side deadline for all model runs of one request; default `10s`.
- `MAX_CONCURRENT_REQUESTS`: admitted requests including inference waiters; default `8`. Excess requests receive `503` with `Retry-After`.
- `PORT`: listen port; default `5001`.

Startup fails with an error when a value cannot be parsed or is out of range.

Inference is serialized per process to protect model state, with a bounded admitted-request queue. The request body is read and validated before a request is admitted, so a slow client does not occupy a queue place. Scale replicas for concurrency and benchmark the chosen model on the target CPU architecture.

A model run cannot be interrupted. When a request times out, the caller gets `504` at once, but the run keeps the inference slot until it has really finished, and later requests wait for it. Timed-out requests therefore never add parallel model runs, and at most one abandoned run exists at a time; under sustained overload callers see `504` and `503` instead. On shutdown the process waits up to 10 seconds for a running inference before it tears the session down.

## Connect Synit WAF

The guard is called only for tenants whose `llm_protection.mode` is `ml` or `hybrid`:

```yaml
tenants:
  "api.example.com":
    security:
      waf_enabled: true              # required by hybrid mode
      include_rule_sets:
        - "llm-protection"           # static rules of hybrid mode
      llm_protection:
        enabled: true
        mode: "hybrid"               # rules | ml | hybrid
        action: "audit"              # start with audit, then deny
        threshold: 0.85
        fail_mode: "open"            # open | closed, for sidecar failures
        timeout: "500ms"
        sidecar_url: "http://localhost:5001/v1/detect"
        sidecar_token_env: "SYNIT_LLM_GUARD_TOKEN"
        inspect_paths: ["/v1/chat/completions", "/v1/messages"]
        inspect_json_fields: ["prompt", "input", "query", "messages[].content"]
```

`sidecar_token_env` names the environment variable that holds `AUTH_TOKEN`; the WAF also reads `<name>_FILE` for a mounted secret. A plain `http://` sidecar URL is accepted only for loopback, or when `global_settings.allow_insecure_service_urls` is set for a trusted private network.

How the WAF uses the guard:

- It extracts the configured JSON fields, or the whole body for `text/plain`, from requests under `inspect_paths`.
- It splits texts above `max_text_bytes` (default `8192`) into overlapping chunks and sends at most `sidecar_max_batch` (default `32`) texts per call. Keep `MAX_TEXT_BYTES` and `MAX_TEXTS` at or above these two values.
- All calls of one request share the `timeout` budget, and the remaining budget is sent as `max_latency_ms`. Measure the model on the target CPU and set `timeout` from the result; the default of 500 ms is a starting point.
- It applies `threshold` to the highest score and caches scores for ten minutes per tenant, path, and text.
- A timeout, a connection error, `401`, `503`, or `504` is a dependency failure and follows `fail_mode`.
- `400`, `413`, or `422` means the input cannot be inspected. With `action: deny` the WAF answers `422` regardless of `fail_mode`; with `action: audit` it logs and forwards the request.

## Long texts

The tokenizer truncates every input at the model's token window (`max_position_embeddings`, often 512 tokens) without an error. Text behind the window would never be scored, so the guard splits each text longer than `CHUNK_BYTES` into overlapping chunks, scores every chunk, and reports the highest chunk score as the score of that text. The response still holds exactly one score per submitted text, in input order.

Chunks are cut in bytes on UTF-8 character boundaries because counting tokens would need a tokenizer pass of its own. Choose `CHUNK_BYTES` so that one chunk always fits the token window of your model. Token-dense input such as non-Latin scripts, base64, or symbol runs can reach one token per byte, and a chunk that exceeds the window is truncated silently again. An attacker controls the text, so the default is the only value that can never be truncated on a 512-token model: the token window minus the special tokens, `510`. A larger value such as `1024` halves the number of chunks for English prose at roughly four bytes per token, but it lets dense filler push a payload out of the scored window. Raise it only for a model with a larger window.

`CHUNK_OVERLAP_BYTES` decides how large a phrase may be and still be seen whole by one chunk when it straddles a cut. Keep it well below `CHUNK_BYTES`: a text produces about `len / (CHUNK_BYTES - CHUNK_OVERLAP_BYTES)` chunks, chunks run in batches of at most `MAX_TEXTS`, and all batches of a request share one inference deadline.

## API

`POST /v1/detect` requires `Content-Type: application/json` and `Authorization: Bearer <AUTH_TOKEN>`:

```json
{
  "tenant": "api.example.com",
  "path": "/v1/chat",
  "texts": ["user prompt"],
  "max_latency_ms": 1000
}
```

The response:

```json
{
  "verdict": "injection",
  "score": 0.97,
  "scores": [0.97],
  "model": "prompt-injection-v1",
  "reason": "text_classification"
}
```

`scores` is authoritative: it holds one injection probability per submitted text, in input order, and the WAF applies its own policy threshold to it. `score` is the maximum of `scores`. `verdict` is advisory only: it is `injection` when `score` reaches this service's `INJECTION_THRESHOLD`, which can differ from the WAF threshold. The WAF ignores `verdict`. The field stays for compatibility and for manual checks with `curl`.

Status codes:

- `400`: malformed JSON, unknown fields, missing `tenant`, `path` or `texts`, an empty text, or more than `MAX_TEXTS` texts. The over-limit body starts with `too many texts`.
- `413`: a text above `MAX_TEXT_BYTES` (body starts with `text too large`) or a request above `MAX_REQUEST_BYTES` (`Request body too large`).
- `401`, `405`, `415`: missing or wrong bearer token, method, or content type.
- `503`: the admission queue is full (with `Retry-After`) or inference failed.
- `504`: the inference deadline passed, either `MAX_INFERENCE_TIMEOUT` or a shorter `max_latency_ms` from the request.

See [Connect Synit WAF](#connect-synit-waf) for how the WAF maps these status codes to its `fail_mode` and `action`.

Liveness is available at `/livez` and `/health`; readiness is available at `/readyz`. The model loads before the server starts, so readiness implies successful initialization.

## Container

Release images are published as `synitio/synit-llm-guard:<version>` on Docker Hub; they contain no model. Pin production deployments by digest. To build from source:

```bash
docker build -t synit-llm-guard:local .
docker run --rm -p 127.0.0.1:5001:5001 \
  -e AUTH_TOKEN='replace-with-a-long-random-token' \
  -e MODEL_PATH=/models/model \
  -v /absolute/path/to/model:/models/model:ro \
  synit-llm-guard:local
```

Keep port `5001` on a private network. Bearer authentication does not encrypt traffic; use TLS or a trusted workload network between separate hosts.

## Verification

```bash
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go vet ./...
go test -race -count=1 ./...
```
