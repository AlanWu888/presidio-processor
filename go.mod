module github.com/your-org/presidioprocessor

go 1.26.0

// Versions match OpenTelemetry Collector v0.161.0 (stable modules v1.67.0).
// Run `go mod tidy` after cloning to resolve indirect dependencies and go.sum.
require (
	go.opentelemetry.io/collector/component v1.67.0
	go.opentelemetry.io/collector/component/componenttest v0.161.0
	go.opentelemetry.io/collector/config/confighttp v0.161.0
	go.opentelemetry.io/collector/config/configopaque v1.67.0
	go.opentelemetry.io/collector/confmap v1.67.0
	go.opentelemetry.io/collector/consumer v1.67.0
	go.opentelemetry.io/collector/consumer/consumertest v0.161.0
	go.opentelemetry.io/collector/pdata v1.67.0
	go.opentelemetry.io/collector/processor v1.67.0
	go.opentelemetry.io/collector/processor/processorhelper v0.161.0
	go.opentelemetry.io/collector/processor/processortest v0.161.0
	go.uber.org/zap v1.28.0
)
