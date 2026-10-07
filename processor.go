package presidioprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
	"go.uber.org/zap"

	"github.com/your-org/presidioprocessor/internal/redact"
)

type presidioProcessor struct {
	cfg       *Config
	logger    *zap.Logger
	telemetry component.TelemetrySettings
	keys      redact.KeyMatcher
	batchOpts redact.BatchOptions
	redactor  *redact.Redactor
}

func newPresidioProcessor(cfg *Config, set processor.Settings) *presidioProcessor {
	return &presidioProcessor{
		cfg:       cfg,
		logger:    set.Logger,
		telemetry: set.TelemetrySettings,
		keys:      redact.NewKeyMatcher(cfg.Attributes),
		batchOpts: redact.BatchOptions{
			JSONAware:  cfg.JSONAware,
			SkipFields: cfg.JSONSkipFields,
			MinLength:  cfg.MinLength,
		},
	}
}

// start builds the HTTP client. It runs once the collector's extensions
// exist, which confighttp needs for auth extensions.
func (p *presidioProcessor) start(ctx context.Context, host component.Host) error {
	client, err := p.cfg.Analyzer.ToClient(ctx, host.GetExtensions(), p.telemetry)
	if err != nil {
		return err
	}
	a := p.cfg.Analyzer
	p.redactor = &redact.Redactor{
		Analyzer: &redact.HTTPAnalyzer{
			Client:         client,
			Endpoint:       a.Endpoint,
			Language:       a.Language,
			Entities:       a.Entities,
			ScoreThreshold: a.ScoreThreshold,
			AllowList:      a.AllowList,
			BatchRequests:  a.BatchRequests,
			MaxBatchSize:   a.MaxBatchSize,
		},
		Masker: redact.Masker{
			Operator: redact.Operator(p.cfg.Operator),
			HashKey:  []byte(p.cfg.HashKey),
		},
	}
	p.logger.Info("Presidio processor started",
		zap.String("analyzer", a.Endpoint),
		zap.Int("attribute_patterns", len(p.cfg.Attributes)),
		zap.String("on_error", string(p.cfg.OnError)),
	)
	return nil
}

func (p *presidioProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	b := redact.NewBatch(p.batchOpts)
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		if p.cfg.ScanResourceAttributes {
			p.collectAttributes(b, rs.Resource().Attributes())
		}
		sss := rs.ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			spans := sss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				p.collectAttributes(b, span.Attributes())
				if p.cfg.ScanSpanEvents {
					events := span.Events()
					for e := 0; e < events.Len(); e++ {
						p.collectAttributes(b, events.At(e).Attributes())
					}
				}
			}
		}
	}
	return td, p.run(ctx, b, td.SpanCount())
}

func (p *presidioProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	b := redact.NewBatch(p.batchOpts)
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		if p.cfg.ScanResourceAttributes {
			p.collectAttributes(b, rl.Resource().Attributes())
		}
		sls := rl.ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			records := sls.At(j).LogRecords()
			for k := 0; k < records.Len(); k++ {
				lr := records.At(k)
				p.collectAttributes(b, lr.Attributes())
				if p.cfg.ScanLogBody {
					p.collectValue(b, lr.Body())
				}
			}
		}
	}
	return ld, p.run(ctx, b, ld.LogRecordCount())
}

// run redacts the batch and maps a failure to the configured behaviour.
// The returned error is what processorhelper sees: nil forwards the data,
// ErrSkipProcessingData drops it, anything else is returned upstream.
func (p *presidioProcessor) run(ctx context.Context, b *redact.Batch, items int) error {
	if b.Len() == 0 {
		return nil
	}
	st, err := p.redactor.Run(ctx, b)
	if err == nil {
		p.logger.Debug("Redacted batch",
			zap.Int("items", items),
			zap.Int("texts", st.Texts),
			zap.Int("unique_texts", st.Unique),
			zap.Int("entities", st.Entities),
			zap.Int("changed", st.Changed),
		)
		return nil
	}

	// err never contains payload content, so it is safe to log.
	switch p.cfg.OnError {
	case OnErrorPassthrough:
		p.logger.Warn("Presidio analysis failed; forwarding data UNREDACTED (on_error: passthrough)",
			zap.Error(err), zap.Int("items", items))
		return nil
	case OnErrorReject:
		p.logger.Error("Presidio analysis failed; rejecting data (on_error: reject)",
			zap.Error(err), zap.Int("items", items))
		return err
	default:
		p.logger.Error("Presidio analysis failed; dropping data (on_error: drop)",
			zap.Error(err), zap.Int("items", items))
		return processorhelper.ErrSkipProcessingData
	}
}

func (p *presidioProcessor) collectAttributes(b *redact.Batch, attrs pcommon.Map) {
	attrs.Range(func(k string, v pcommon.Value) bool {
		if p.keys.Match(k) {
			p.collectValue(b, v)
		}
		return true
	})
}

// collectValue queues every string inside v. Nested maps and slices are
// walked, so array-valued attributes are covered too. The setter writes back
// into the same pcommon.Value; that is safe because the batch only runs after
// collection finishes and nothing adds or removes keys in between.
func (p *presidioProcessor) collectValue(b *redact.Batch, v pcommon.Value) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		target := v
		b.Add(v.Str(), func(s string) { target.SetStr(s) })
	case pcommon.ValueTypeMap:
		v.Map().Range(func(_ string, inner pcommon.Value) bool {
			p.collectValue(b, inner)
			return true
		})
	case pcommon.ValueTypeSlice:
		s := v.Slice()
		for i := 0; i < s.Len(); i++ {
			p.collectValue(b, s.At(i))
		}
	}
}
