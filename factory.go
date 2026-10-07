// Package presidioprocessor is an OpenTelemetry Collector processor that
// redacts PII from span attributes and logs using a Presidio analyzer service.
package presidioprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

const stability = component.StabilityLevelDevelopment

// componentType is the key used under "processors:" in collector config.
var componentType = component.MustNewType("presidio")

var processorCapabilities = consumer.Capabilities{MutatesData: true}

// NewFactory returns the factory to list in your OCB manifest.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		componentType,
		createDefaultConfig,
		processor.WithTraces(createTraces, stability),
		processor.WithLogs(createLogs, stability),
	)
}

func createTraces(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Traces) (processor.Traces, error) {
	p := newPresidioProcessor(cfg.(*Config), set)
	return processorhelper.NewTraces(ctx, set, cfg, next, p.processTraces,
		processorhelper.WithStart(p.start),
		processorhelper.WithCapabilities(processorCapabilities),
	)
}

func createLogs(ctx context.Context, set processor.Settings, cfg component.Config, next consumer.Logs) (processor.Logs, error) {
	p := newPresidioProcessor(cfg.(*Config), set)
	return processorhelper.NewLogs(ctx, set, cfg, next, p.processLogs,
		processorhelper.WithStart(p.start),
		processorhelper.WithCapabilities(processorCapabilities),
	)
}
