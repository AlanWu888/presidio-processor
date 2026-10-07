# Presidio processor for the OpenTelemetry Collector

A collector processor that redacts PII from trace and log content using a
[Presidio](https://github.com/data-privacy-stack/presidio) analyzer service.
Built for the centralised-redaction PoC: every source sending to Langfuse
passes through one redaction policy in the collector.

Targets OpenTelemetry Collector **v0.161.0** (stable modules v1.67.0), Go 1.26.

## How it works

1. For each payload, the processor collects every string it should scan:
   matching span attributes, span event attributes, log attributes and log
   bodies. Array and map values are walked too.
2. JSON values (such as `gen_ai.input.messages`) are parsed, and only their
   string leaves are scanned. Structural keys like `role` and `type` are
   skipped, and JSON nested inside strings (tool call arguments) is parsed as
   well, so messages still render in Langfuse after redaction.
3. Identical strings are deduplicated, then sent to Presidio's `/analyze`
   endpoint in batches.
4. Detected entities are masked locally, either as `<PERSON>` or as a keyed
   hash like `<PERSON_3f9a1c2b7d4e>` that stays the same for the same value.
   Overlapping findings are merged. Only the analyzer service is needed, not
   the anonymizer.
5. Values are written back only after the whole payload has been analysed. If
   the analyzer fails, nothing is modified and `on_error` decides what happens.

Errors and logs never include payload content.

### Differences from mxab/otel-presidio

- Plain HTTP to Presidio's REST API via `confighttp`, so TLS, headers and auth
  work out of the box.
- Explicit, tested failure modes (`drop`, `reject`, `passthrough`).
- JSON-aware redaction and prefix matching for attribute keys.
- No separate anonymiser service to run.

## Configuration

```yaml
processors:
  presidio:
    analyzer:
      endpoint: http://presidio-analyzer:3000   # plus any confighttp client setting:
      timeout: 5s                               # tls, headers, auth, ...
      language: en
      score_threshold: 0.5
      entities: []          # empty = all entities the analyzer supports
      allow_list: []        # values never redacted
      batch_requests: true  # false for analyzers that only accept one text per call
      max_batch_size: 100
    attributes: [...]       # exact keys, "prefix.*", or "*" (see defaults below)
    scan_resource_attributes: false
    scan_span_events: true
    scan_log_body: true
    json_aware: true
    json_skip_fields: [role, type, finish_reason, id, tool_call_id, mime_type, modality]
    min_length: 3
    operator: replace       # or hash
    hash_key: ${env:PRESIDIO_HASH_KEY}   # required for hash
    on_error: drop          # drop | reject | passthrough
```

| `on_error` | Data exported? | Upstream sees | Use when |
| --- | --- | --- | --- |
| `drop` (default) | No | Success, so no retries | Losing some telemetry is acceptable |
| `reject` | No | An error, so senders may retry | You want backpressure and retries |
| `passthrough` | Yes, **unredacted** | Success | Never for Langfuse; debugging only |

Default `attributes` cover the GenAI semantic conventions
(`gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions`,
tool call arguments and results, retrieval query text), OpenLLMetry-style
`gen_ai.prompt*` and `gen_ai.completion*`, Langfuse `langfuse.observation.*` and
`langfuse.trace.*` input/output, and OpenInference `input.value`,
`output.value`, `llm.input_messages.*` and `llm.output_messages.*`. Treat them
as a starting point and replace them with the inventory from your own traces.

## Build and test

```bash
go mod tidy          # resolves indirect deps and writes go.sum
go test ./...

go install go.opentelemetry.io/collector/cmd/builder@v0.161.0
builder --config examples/builder-config.yaml
./_build/otelcol-presidio --config examples/collector-config.yaml
```

Or with Docker, from the repository root:

```bash
docker build -t otelcol-presidio -f examples/Dockerfile .
cd examples && LANGFUSE_HOST=... LANGFUSE_AUTH=... docker compose up
```

Behind a TLS-inspecting corporate proxy, the Docker build can fail with
`x509: certificate signed by unknown authority`. Either add your root CA to
`examples/certs/` (see the Dockerfile), or build on the host, which already
trusts it, and only package the binary in Docker:

```bash
./examples/build-local.sh                 # builds for Docker Desktop's architecture
ARCH=amd64 ./examples/build-local.sh      # e.g. for an amd64 cluster
```

Before building, change the module path `github.com/your-org/presidioprocessor`
in `go.mod`, the imports, and `examples/builder-config.yaml` to your repository.

## PoC test plan

- **Detection.** Send labelled synthetic prompts (never real data) and compare
  what reached Langfuse with what should have been masked. Tune
  `score_threshold`, `entities` and `allow_list`, and add custom recognisers to
  the analyzer where needed.
- **Coverage.** Capture traces from each source with the `debug` exporter in
  dev and check every content-bearing key is matched by `attributes`.
- **Throughput.** Replay traces at expected volume and 2–3× headroom. Watch
  analyzer CPU, collector queue depth and the `timeout`.
- **Failure.** Stop the analyzer mid-run and confirm nothing unredacted reaches
  Langfuse with `on_error: drop` and `reject`.
- **Usability.** Open redacted traces in Langfuse and check chat messages still
  render.

## Known limitations

- Batched `/analyze` requests (`"text"` as a list) need a recent analyzer
  image. With older images, set `batch_requests: false`; calls are then
  sequential, one per distinct string.
- Re-serialised JSON has its keys sorted alphabetically. Values are unchanged
  apart from redactions.
- The processor reports activity in debug logs only; it does not emit its own
  metrics yet.
- Already-redacted LiteLLM traffic is not skipped automatically. Use the
  routing connector to send it around this processor.
