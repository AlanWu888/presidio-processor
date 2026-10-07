package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Operator decides what replaces a detected entity.
type Operator string

const (
	// OperatorReplace swaps the entity for its type, e.g. "<PERSON>".
	OperatorReplace Operator = "replace"
	// OperatorHash swaps the entity for a keyed hash, e.g. "<PERSON_3f9a1c2b7d4e>".
	// The same value always maps to the same token, so traces stay debuggable
	// (you can see that two spans mention the same person) without exposing it.
	OperatorHash Operator = "hash"
)

// Masker applies an Operator to analyzer results.
type Masker struct {
	Operator Operator
	HashKey  []byte
}

type span struct {
	start, end int
	typ        string
	score      float64
}

// Mask returns text with every entity replaced. Entity offsets are code-point
// indices, so the text is handled as runes. Overlapping entities are merged
// into one replacement labelled with the highest-scoring type.
func (m Masker) Mask(text string, ents []Entity) string {
	if len(ents) == 0 {
		return text
	}
	runes := []rune(text)
	spans := mergeSpans(ents, len(runes))
	if len(spans) == 0 {
		return text
	}

	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, s := range spans {
		b.WriteString(string(runes[last:s.start]))
		b.WriteString(m.token(s.typ, string(runes[s.start:s.end])))
		last = s.end
	}
	b.WriteString(string(runes[last:]))
	return b.String()
}

func (m Masker) token(typ, original string) string {
	if m.Operator == OperatorHash {
		mac := hmac.New(sha256.New, m.HashKey)
		mac.Write([]byte(original))
		return "<" + typ + "_" + hex.EncodeToString(mac.Sum(nil))[:12] + ">"
	}
	return "<" + typ + ">"
}

// mergeSpans clamps entities to the text, drops empty ones, and merges
// overlaps so every character is replaced at most once.
func mergeSpans(ents []Entity, n int) []span {
	spans := make([]span, 0, len(ents))
	for _, e := range ents {
		start, end := e.Start, e.End
		if start < 0 {
			start = 0
		}
		if end > n {
			end = n
		}
		if start >= end {
			continue
		}
		spans = append(spans, span{start: start, end: end, typ: e.Type, score: e.Score})
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})

	merged := spans[:0]
	for _, s := range spans {
		if len(merged) > 0 {
			cur := &merged[len(merged)-1]
			if s.start < cur.end {
				if s.end > cur.end {
					cur.end = s.end
				}
				if s.score > cur.score {
					cur.score = s.score
					cur.typ = s.typ
				}
				continue
			}
		}
		merged = append(merged, s)
	}
	return merged
}
