package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// BatchOptions control how values are queued for analysis.
type BatchOptions struct {
	// JSONAware parses values that look like JSON objects or arrays and only
	// scans their string leaves, so the structure survives redaction.
	JSONAware bool
	// SkipFields are JSON object keys whose values are never scanned
	// (e.g. "role", "type"). Only used when JSONAware is true.
	SkipFields []string
	// MinLength skips strings shorter than this many characters (after
	// trimming), which avoids analyzer calls for values like "ok" or "en".
	MinLength int
}

// Batch collects every string to redact from one pdata payload, so the
// analyzer is called once per payload instead of once per attribute.
// Setters are only applied after analysis succeeds for the whole batch,
// so a failed call never leaves data half-redacted.
type Batch struct {
	opts    BatchOptions
	skip    map[string]struct{}
	texts   []string
	setters []func(string)
	finals  []func()
}

// NewBatch creates an empty batch.
func NewBatch(opts BatchOptions) *Batch {
	skip := make(map[string]struct{}, len(opts.SkipFields))
	for _, f := range opts.SkipFields {
		skip[f] = struct{}{}
	}
	return &Batch{opts: opts, skip: skip}
}

// Len is the number of strings queued for analysis.
func (b *Batch) Len() int { return len(b.texts) }

// Add queues s for redaction. set is called with the redacted value if
// anything in s changed.
func (b *Batch) Add(s string, set func(string)) {
	if b.tooShort(s) {
		return
	}
	if b.opts.JSONAware && b.addJSON(s, set) {
		return
	}
	b.texts = append(b.texts, s)
	b.setters = append(b.setters, set)
}

func (b *Batch) tooShort(s string) bool {
	return utf8.RuneCountInString(strings.TrimSpace(s)) < b.opts.MinLength
}

// addJSON handles s as JSON if it is a well-formed object or array.
// It returns false (and queues nothing) if s is not JSON.
func (b *Batch) addJSON(s string, set func(string)) bool {
	t := strings.TrimSpace(s)
	if t == "" || (t[0] != '{' && t[0] != '[') {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(t))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		return false // trailing data: treat as plain text
	}

	changed := false
	b.walk(root, func(n any) { root = n }, &changed)

	// Registered after walking, so finalizers of JSON nested inside this
	// value run first and the parent re-serialises their output.
	b.finals = append(b.finals, func() {
		if !changed {
			return
		}
		out, err := marshalJSON(root)
		if err != nil {
			// Never fall back to the original value: it may contain PII.
			set("<REDACTED>")
			return
		}
		set(out)
	})
	return true
}

func (b *Batch) walk(node any, assign func(any), changed *bool) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if _, skip := b.skip[k]; skip {
				continue
			}
			k := k
			b.walk(child, func(n any) { v[k] = n }, changed)
		}
	case []any:
		for i, child := range v {
			i := i
			b.walk(child, func(n any) { v[i] = n }, changed)
		}
	case string:
		if b.tooShort(v) {
			return
		}
		mark := func(n string) {
			assign(n)
			*changed = true
		}
		// Strings inside JSON can themselves be JSON, e.g. tool call
		// arguments. Parse those too rather than scanning escaped text.
		if b.addJSON(v, mark) {
			return
		}
		b.texts = append(b.texts, v)
		b.setters = append(b.setters, mark)
	}
}

func marshalJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "<PERSON>" readable instead of "\u003cPERSON\u003e"
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// Stats describe one Run.
type Stats struct {
	Texts    int // strings queued
	Unique   int // distinct strings sent to the analyzer
	Entities int // entities found
	Changed  int // queued strings that were modified
}

// Redactor runs batches through an Analyzer and a Masker.
type Redactor struct {
	Analyzer Analyzer
	Masker   Masker
}

// Run analyzes every queued string and applies the masked values.
// On error nothing in the batch is modified.
func (r *Redactor) Run(ctx context.Context, b *Batch) (Stats, error) {
	st := Stats{Texts: len(b.texts)}
	if len(b.texts) == 0 {
		return st, nil
	}

	// The same prompt often appears in several spans (e.g. a parent and a
	// child span), so analyze each distinct string once.
	index := make(map[string]int, len(b.texts))
	unique := make([]string, 0, len(b.texts))
	slot := make([]int, len(b.texts))
	for i, t := range b.texts {
		j, ok := index[t]
		if !ok {
			j = len(unique)
			index[t] = j
			unique = append(unique, t)
		}
		slot[i] = j
	}
	st.Unique = len(unique)

	results, err := r.Analyzer.Analyze(ctx, unique)
	if err != nil {
		return st, err
	}
	if len(results) != len(unique) {
		return st, fmt.Errorf("analyzer returned %d results for %d texts", len(results), len(unique))
	}

	masked := make([]string, len(unique))
	changed := make([]bool, len(unique))
	for j, t := range unique {
		if len(results[j]) == 0 {
			continue
		}
		st.Entities += len(results[j])
		masked[j] = r.Masker.Mask(t, results[j])
		changed[j] = masked[j] != t
	}

	for i, set := range b.setters {
		if j := slot[i]; changed[j] {
			set(masked[j])
			st.Changed++
		}
	}
	for _, f := range b.finals {
		f()
	}
	return st, nil
}
