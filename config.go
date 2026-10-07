package presidioprocessor

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"

	"github.com/your-org/presidioprocessor/internal/redact"
)

// OnError controls what happens to a payload when the analyzer call fails.
type OnError string

const (
	// OnErrorDrop discards the payload. Nothing unredacted is exported and the
	// sender is told the data was accepted (no retries). This is the default.
	OnErrorDrop OnError = "drop"
	// OnErrorReject returns the error upstream. Nothing unredacted is exported;
	// the receiver reports a failure, so senders may retry.
	OnErrorReject OnError = "reject"
	// OnErrorPassthrough forwards the payload unredacted (fail open).
	// Only use this when losing telemetry is worse than leaking PII.
	OnErrorPassthrough OnError = "passthrough"
)

// AnalyzerConfig points at a Presidio analyzer service. The embedded HTTP
// client settings give you endpoint, timeout, TLS, headers and auth.
type AnalyzerConfig struct {
	confighttp.ClientConfig `mapstructure:",squash"`

	// Language passed to Presidio, e.g. "en".
	Language string `mapstructure:"language"`
	// Entities restricts detection to these Presidio entity types.
	// Empty means every entity the analyzer supports.
	Entities []string `mapstructure:"entities"`
	// ScoreThreshold drops findings below this confidence (0 to 1).
	ScoreThreshold float64 `mapstructure:"score_threshold"`
	// AllowList holds values that are never redacted (e.g. your company name).
	AllowList []string `mapstructure:"allow_list"`
	// BatchRequests sends many texts per request. Turn off for analyzer
	// versions whose /analyze endpoint only accepts a single string.
	BatchRequests bool `mapstructure:"batch_requests"`
	// MaxBatchSize caps texts per request when BatchRequests is on.
	MaxBatchSize int `mapstructure:"max_batch_size"`
}

// Config is the processor configuration.
type Config struct {
	Analyzer AnalyzerConfig `mapstructure:"analyzer"`

	// Attributes lists the attribute keys to scan. Use a trailing "*" for a
	// prefix match ("llm.input_messages.*") or "*" alone for every key.
	Attributes []string `mapstructure:"attributes"`
	// ScanResourceAttributes also applies Attributes to resource attributes.
	ScanResourceAttributes bool `mapstructure:"scan_resource_attributes"`
	// ScanSpanEvents also applies Attributes to span event attributes,
	// where older GenAI instrumentations record prompts.
	ScanSpanEvents bool `mapstructure:"scan_span_events"`
	// ScanLogBody scans every string in log record bodies.
	ScanLogBody bool `mapstructure:"scan_log_body"`

	// JSONAware parses JSON values and only scans their string leaves, so
	// message structures still render in Langfuse after redaction.
	JSONAware bool `mapstructure:"json_aware"`
	// JSONSkipFields are JSON keys that are never scanned (e.g. "role").
	JSONSkipFields []string `mapstructure:"json_skip_fields"`
	// MinLength skips strings shorter than this many characters.
	MinLength int `mapstructure:"min_length"`

	// Operator is "replace" (<PERSON>) or "hash" (<PERSON_3f9a1c2b7d4e>).
	Operator string `mapstructure:"operator"`
	// HashKey is the secret for the "hash" operator. Keep it out of the
	// config file, e.g. hash_key: ${env:PRESIDIO_HASH_KEY}.
	HashKey configopaque.String `mapstructure:"hash_key"`

	// OnError is "drop" (default), "reject" or "passthrough".
	OnError OnError `mapstructure:"on_error"`
}

var _ component.Config = (*Config)(nil)

// DefaultAttributes covers the content-bearing keys of the GenAI semantic
// conventions, OpenLLMetry, Langfuse and OpenInference. Check them against
// real traces from your sources and extend as needed.
var DefaultAttributes = []string{
	// OpenTelemetry GenAI semantic conventions
	"gen_ai.input.messages",
	"gen_ai.output.messages",
	"gen_ai.system_instructions",
	"gen_ai.tool.call.arguments",
	"gen_ai.tool.call.result",
	"gen_ai.retrieval.query.text",
	// Older/OpenLLMetry-style keys (gen_ai.prompt.0.content, ...)
	"gen_ai.prompt*",
	"gen_ai.completion*",
	// Langfuse
	"langfuse.observation.input",
	"langfuse.observation.output",
	"langfuse.trace.input",
	"langfuse.trace.output",
	// OpenInference
	"input.value",
	"output.value",
	"llm.input_messages.*",
	"llm.output_messages.*",
}

// DefaultJSONSkipFields are structural keys in message JSON that never hold PII.
var DefaultJSONSkipFields = []string{"role", "type", "finish_reason", "id", "tool_call_id", "mime_type", "modality"}

func createDefaultConfig() component.Config {
	httpCfg := confighttp.NewDefaultClientConfig()
	httpCfg.Endpoint = "http://localhost:3000"
	httpCfg.Timeout = 10 * time.Second

	return &Config{
		Analyzer: AnalyzerConfig{
			ClientConfig:   httpCfg,
			Language:       "en",
			ScoreThreshold: 0.5,
			BatchRequests:  true,
			MaxBatchSize:   100,
		},
		Attributes:     append([]string(nil), DefaultAttributes...),
		ScanSpanEvents: true,
		ScanLogBody:    true,
		JSONAware:      true,
		JSONSkipFields: append([]string(nil), DefaultJSONSkipFields...),
		MinLength:      3,
		Operator:       string(redact.OperatorReplace),
		OnError:        OnErrorDrop,
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if c.Analyzer.Endpoint == "" {
		errs = append(errs, errors.New("analyzer.endpoint must be set"))
	}
	if c.Analyzer.Language == "" {
		errs = append(errs, errors.New("analyzer.language must be set"))
	}
	if c.Analyzer.ScoreThreshold < 0 || c.Analyzer.ScoreThreshold > 1 {
		errs = append(errs, errors.New("analyzer.score_threshold must be between 0 and 1"))
	}
	if c.Analyzer.BatchRequests && c.Analyzer.MaxBatchSize <= 0 {
		errs = append(errs, errors.New("analyzer.max_batch_size must be positive"))
	}
	if len(c.Attributes) == 0 && !c.ScanLogBody {
		errs = append(errs, errors.New("nothing to scan: set attributes or enable scan_log_body"))
	}
	if c.MinLength < 0 {
		errs = append(errs, errors.New("min_length cannot be negative"))
	}
	switch redact.Operator(c.Operator) {
	case redact.OperatorReplace:
	case redact.OperatorHash:
		if c.HashKey == "" {
			errs = append(errs, errors.New(`hash_key must be set when operator is "hash"`))
		}
	default:
		errs = append(errs, fmt.Errorf(`operator must be "replace" or "hash", got %q`, c.Operator))
	}
	switch c.OnError {
	case OnErrorDrop, OnErrorReject, OnErrorPassthrough:
	default:
		errs = append(errs, fmt.Errorf(`on_error must be "drop", "reject" or "passthrough", got %q`, c.OnError))
	}
	return errors.Join(errs...)
}
