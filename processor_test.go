package presidioprocessor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
)

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// fakeAnalyzer answers /analyze like Presidio, detecting email addresses only.
func fakeAnalyzer(t *testing.T) *httptest.Server {
	t.Helper()
	find := func(s string) []map[string]any {
		var out []map[string]any
		for _, loc := range emailRe.FindAllStringIndex(s, -1) {
			out = append(out, map[string]any{
				"entity_type": "EMAIL_ADDRESS",
				"start":       utf8.RuneCountInString(s[:loc[0]]),
				"end":         utf8.RuneCountInString(s[:loc[1]]),
				"score":       1.0,
			})
		}
		return out
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text []string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		res := make([][]map[string]any, len(req.Text))
		for i, s := range req.Text {
			res[i] = find(s)
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func failingAnalyzer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(endpoint string) *Config {
	cfg := createDefaultConfig().(*Config)
	cfg.Analyzer.Endpoint = endpoint
	return cfg
}

func sampleTraces() ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetName("chat")
	span.Attributes().PutStr("gen_ai.input.messages",
		`[{"role":"user","parts":[{"type":"text","content":"Reply to jane@example.com"}]}]`)
	span.Attributes().PutStr("llm.input_messages.0.message.content", "cc bob@example.org")
	span.Attributes().PutStr("http.request.header.from", "not-scanned@example.com")
	span.Events().AppendEmpty().Attributes().PutStr("gen_ai.prompt", "event text sam@example.net")
	return td
}

func startTraces(t *testing.T, cfg *Config, sink *consumertest.TracesSink) func(ptrace.Traces) error {
	t.Helper()
	ctx := context.Background()
	f := NewFactory()
	proc, err := f.CreateTraces(ctx, processortest.NewNopSettings(componentType), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Shutdown(ctx) })
	return func(td ptrace.Traces) error { return proc.ConsumeTraces(ctx, td) }
}

func attr(t *testing.T, td ptrace.Traces, key string) string {
	t.Helper()
	v, ok := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().Get(key)
	if !ok {
		t.Fatalf("attribute %q missing", key)
	}
	return v.Str()
}

func TestTracesAreRedacted(t *testing.T) {
	sink := new(consumertest.TracesSink)
	consume := startTraces(t, testConfig(fakeAnalyzer(t).URL), sink)

	if err := consume(sampleTraces()); err != nil {
		t.Fatal(err)
	}
	if len(sink.AllTraces()) != 1 {
		t.Fatalf("expected one payload, got %d", len(sink.AllTraces()))
	}
	td := sink.AllTraces()[0]

	msgs := attr(t, td, "gen_ai.input.messages")
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(msgs), &parsed); err != nil {
		t.Fatalf("messages are no longer valid JSON: %s", msgs)
	}
	if !strings.Contains(msgs, "Reply to <EMAIL_ADDRESS>") || !strings.Contains(msgs, `"role":"user"`) {
		t.Errorf("messages not redacted as expected: %s", msgs)
	}
	if got := attr(t, td, "llm.input_messages.0.message.content"); got != "cc <EMAIL_ADDRESS>" {
		t.Errorf("prefix-matched attribute: got %q", got)
	}
	if got := attr(t, td, "http.request.header.from"); got != "not-scanned@example.com" {
		t.Errorf("unlisted attribute should be untouched, got %q", got)
	}
	ev, _ := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Events().At(0).Attributes().Get("gen_ai.prompt")
	if ev.Str() != "event text <EMAIL_ADDRESS>" {
		t.Errorf("span event attribute: got %q", ev.Str())
	}
}

func TestOnErrorDrop(t *testing.T) {
	sink := new(consumertest.TracesSink)
	consume := startTraces(t, testConfig(failingAnalyzer(t).URL), sink)

	if err := consume(sampleTraces()); err != nil {
		t.Fatalf("drop should not return an error, got %v", err)
	}
	if sink.SpanCount() != 0 {
		t.Error("data must not be exported when analysis fails")
	}
}

func TestOnErrorReject(t *testing.T) {
	cfg := testConfig(failingAnalyzer(t).URL)
	cfg.OnError = OnErrorReject
	sink := new(consumertest.TracesSink)
	consume := startTraces(t, cfg, sink)

	if err := consume(sampleTraces()); err == nil {
		t.Fatal("reject should return an error")
	}
	if sink.SpanCount() != 0 {
		t.Error("data must not be exported when analysis fails")
	}
}

func TestOnErrorPassthrough(t *testing.T) {
	cfg := testConfig(failingAnalyzer(t).URL)
	cfg.OnError = OnErrorPassthrough
	sink := new(consumertest.TracesSink)
	consume := startTraces(t, cfg, sink)

	if err := consume(sampleTraces()); err != nil {
		t.Fatal(err)
	}
	if sink.SpanCount() != 1 {
		t.Fatal("passthrough should forward the data")
	}
	if got := attr(t, sink.AllTraces()[0], "llm.input_messages.0.message.content"); got != "cc bob@example.org" {
		t.Errorf("passthrough must forward the original value, got %q", got)
	}
}

func TestLogsAreRedacted(t *testing.T) {
	ctx := context.Background()
	sink := new(consumertest.LogsSink)
	proc, err := NewFactory().CreateLogs(ctx, processortest.NewNopSettings(componentType), testConfig(fakeAnalyzer(t).URL), sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proc.Shutdown(ctx) }()

	ld := plog.NewLogs()
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Body().SetStr("user jane@example.com signed in")
	lr.Attributes().PutStr("input.value", "from bob@example.org")

	if err := proc.ConsumeLogs(ctx, ld); err != nil {
		t.Fatal(err)
	}
	out := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if out.Body().Str() != "user <EMAIL_ADDRESS> signed in" {
		t.Errorf("log body: got %q", out.Body().Str())
	}
	if v, _ := out.Attributes().Get("input.value"); v.Str() != "from <EMAIL_ADDRESS>" {
		t.Errorf("log attribute: got %q", v.Str())
	}
}
