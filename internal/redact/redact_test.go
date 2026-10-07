package redact

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

// fakePresidio mimics the analyzer's /analyze endpoint. It "detects" every
// email address and every occurrence of the name "Jane Doe", and reports
// offsets in code points like the real (Python) service does.
func fakePresidio(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	find := func(text string) []Entity {
		var out []Entity
		for _, loc := range email.FindAllStringIndex(text, -1) {
			out = append(out, entity("EMAIL_ADDRESS", text, loc[0], loc[1], 1.0))
		}
		for i := strings.Index(text, "Jane Doe"); i >= 0; {
			out = append(out, entity("PERSON", text, i, i+len("Jane Doe"), 0.85))
			next := strings.Index(text[i+1:], "Jane Doe")
			if next < 0 {
				break
			}
			i += next + 1
		}
		return out
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		if r.URL.Path != "/analyze" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Text     json.RawMessage `json:"text"`
			Language string          `json:"language"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Language == "" {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		var many []string
		if err := json.Unmarshal(req.Text, &many); err == nil {
			res := make([][]Entity, len(many))
			for i, s := range many {
				res[i] = find(s)
			}
			_ = json.NewEncoder(w).Encode(res)
			return
		}
		var one string
		_ = json.Unmarshal(req.Text, &one)
		_ = json.NewEncoder(w).Encode(find(one))
	}))
}

// entity converts byte offsets to code-point offsets.
func entity(typ, text string, byteStart, byteEnd int, score float64) Entity {
	return Entity{
		Type:  typ,
		Start: utf8.RuneCountInString(text[:byteStart]),
		End:   utf8.RuneCountInString(text[:byteEnd]),
		Score: score,
	}
}

func newRedactor(url string, batch bool) *Redactor {
	return &Redactor{
		Analyzer: &HTTPAnalyzer{Client: http.DefaultClient, Endpoint: url, Language: "en", BatchRequests: batch, MaxBatchSize: 2},
		Masker:   Masker{Operator: OperatorReplace},
	}
}

func TestPlainTextRedaction(t *testing.T) {
	for _, batch := range []bool{true, false} {
		srv := fakePresidio(t, nil)
		r := newRedactor(srv.URL, batch)
		b := NewBatch(BatchOptions{MinLength: 3})

		var a, c string
		b.Add("Email jane@example.com about the invoice", func(s string) { a = s })
		b.Add("Nothing sensitive here", func(s string) { c = s })

		st, err := r.Run(context.Background(), b)
		if err != nil {
			t.Fatalf("batch=%v: %v", batch, err)
		}
		if a != "Email <EMAIL_ADDRESS> about the invoice" {
			t.Errorf("batch=%v: got %q", batch, a)
		}
		if c != "" {
			t.Errorf("batch=%v: unchanged value should not be set, got %q", batch, c)
		}
		if st.Changed != 1 || st.Entities != 1 {
			t.Errorf("batch=%v: unexpected stats %+v", batch, st)
		}
		srv.Close()
	}
}

func TestCodePointOffsets(t *testing.T) {
	srv := fakePresidio(t, nil)
	defer srv.Close()
	r := newRedactor(srv.URL, true)
	b := NewBatch(BatchOptions{})

	var got string
	b.Add("Café ☕ — contact Jane Doe at jane@example.com 👋", func(s string) { got = s })
	if _, err := r.Run(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	want := "Café ☕ — contact <PERSON> at <EMAIL_ADDRESS> 👋"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOverlappingEntitiesMerge(t *testing.T) {
	m := Masker{Operator: OperatorReplace}
	text := "call Jane Doe now"
	got := m.Mask(text, []Entity{
		{Type: "PERSON", Start: 5, End: 13, Score: 0.9},
		{Type: "LOCATION", Start: 10, End: 13, Score: 0.4},
		{Type: "BOGUS", Start: 40, End: 50, Score: 1}, // out of range: ignored
	})
	if got != "call <PERSON> now" {
		t.Errorf("got %q", got)
	}
}

func TestHashOperatorIsConsistent(t *testing.T) {
	m := Masker{Operator: OperatorHash, HashKey: []byte("k")}
	e := []Entity{{Type: "PERSON", Start: 0, End: 8, Score: 1}}
	a := m.Mask("Jane Doe", e)
	b := m.Mask("Jane Doe", e)
	c := m.Mask("John Roe", e)
	if a != b {
		t.Errorf("same input gave different tokens: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different inputs gave the same token: %q", a)
	}
	if !regexp.MustCompile(`^<PERSON_[0-9a-f]{12}>$`).MatchString(a) {
		t.Errorf("unexpected token format %q", a)
	}
}

func TestJSONAwareKeepsStructure(t *testing.T) {
	srv := fakePresidio(t, nil)
	defer srv.Close()
	r := newRedactor(srv.URL, true)
	b := NewBatch(BatchOptions{JSONAware: true, SkipFields: []string{"role", "type"}, MinLength: 3})

	in := `[{"role":"user","parts":[{"type":"text","content":"I am Jane Doe, mail me at jane@example.com"}]},` +
		`{"role":"assistant","parts":[{"type":"tool_call","name":"lookup","arguments":"{\"email\":\"jane@example.com\",\"limit\":10}"}]}]`
	var got string
	b.Add(in, func(s string) { got = s })
	if _, err := r.Run(context.Background(), b); err != nil {
		t.Fatal(err)
	}

	var msgs []struct {
		Role  string `json:"role"`
		Parts []map[string]any
	}
	if err := json.Unmarshal([]byte(got), &msgs); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, got)
	}
	if msgs[0].Role != "user" || msgs[1].Role != "assistant" {
		t.Errorf("roles changed: %s", got)
	}
	if c := msgs[0].Parts[0]["content"]; c != "I am <PERSON>, mail me at <EMAIL_ADDRESS>" {
		t.Errorf("content not redacted: %v", c)
	}
	// Nested JSON in tool arguments is parsed and redacted, and stays a string.
	args, _ := msgs[1].Parts[0]["arguments"].(string)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(args), &parsed); err != nil {
		t.Fatalf("arguments no longer JSON: %q", args)
	}
	if parsed["email"] != "<EMAIL_ADDRESS>" {
		t.Errorf("nested JSON not redacted: %q", args)
	}
	if strings.Contains(got, "jane@example.com") || strings.Contains(got, "Jane Doe") {
		t.Errorf("PII left in output: %s", got)
	}
}

func TestJSONWithoutPIIIsUntouched(t *testing.T) {
	srv := fakePresidio(t, nil)
	defer srv.Close()
	r := newRedactor(srv.URL, true)
	b := NewBatch(BatchOptions{JSONAware: true, MinLength: 3})

	called := false
	b.Add(`{"b":1, "a":"no secrets in here"}`, func(string) { called = true })
	if _, err := r.Run(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("value without PII should keep its original formatting")
	}
}

func TestInvalidJSONFallsBackToText(t *testing.T) {
	srv := fakePresidio(t, nil)
	defer srv.Close()
	r := newRedactor(srv.URL, true)
	b := NewBatch(BatchOptions{JSONAware: true})

	var got string
	b.Add(`{not json, jane@example.com`, func(s string) { got = s })
	if _, err := r.Run(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if got != `{not json, <EMAIL_ADDRESS>` {
		t.Errorf("got %q", got)
	}
}

func TestDuplicatesAnalyzedOnce(t *testing.T) {
	var calls atomic.Int32
	srv := fakePresidio(t, &calls)
	defer srv.Close()
	r := newRedactor(srv.URL, true) // MaxBatchSize 2
	b := NewBatch(BatchOptions{})

	results := make([]string, 4)
	for i := range results {
		i := i
		b.Add("ping jane@example.com", func(s string) { results[i] = s })
	}
	st, err := r.Run(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if st.Unique != 1 || calls.Load() != 1 {
		t.Errorf("expected 1 unique text and 1 call, got %+v and %d calls", st, calls.Load())
	}
	for _, s := range results {
		if s != "ping <EMAIL_ADDRESS>" {
			t.Errorf("got %q", s)
		}
	}
}

func TestErrorLeavesBatchUntouched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"Jane Doe broke it"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := newRedactor(srv.URL, true)
	b := NewBatch(BatchOptions{JSONAware: true})

	called := false
	b.Add(`{"content":"jane@example.com"}`, func(string) { called = true })
	b.Add("jane@example.com", func(string) { called = true })
	_, err := r.Run(context.Background(), b)
	if err == nil {
		t.Fatal("expected an error")
	}
	if called {
		t.Error("setters must not run when analysis fails")
	}
	if strings.Contains(err.Error(), "Jane") {
		t.Errorf("error leaks response body: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	srv := fakePresidio(t, nil)
	defer srv.Close()
	r := newRedactor(srv.URL, true)
	b := NewBatch(BatchOptions{})
	b.Add("jane@example.com", func(string) {})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Run(ctx, b); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestKeyMatcher(t *testing.T) {
	km := NewKeyMatcher([]string{"gen_ai.input.messages", "llm.input_messages.*"})
	cases := map[string]bool{
		"gen_ai.input.messages":                 true,
		"gen_ai.input.messages.extra":           false,
		"llm.input_messages.0.message.content":  true,
		"llm.output_messages.0.message.content": false,
		"http.method":                           false,
	}
	for k, want := range cases {
		if got := km.Match(k); got != want {
			t.Errorf("Match(%q) = %v, want %v", k, got, want)
		}
	}
	if !NewKeyMatcher([]string{"*"}).Match("anything") {
		t.Error(`"*" should match every key`)
	}
}

func TestMinLengthSkipsShortValues(t *testing.T) {
	b := NewBatch(BatchOptions{MinLength: 3})
	b.Add("ok", func(string) {})
	b.Add("  a ", func(string) {})
	if b.Len() != 0 {
		t.Errorf("short values should be skipped, got %d queued", b.Len())
	}
}
