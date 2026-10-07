// Package redact holds the collector-independent redaction engine: it talks to
// Presidio's analyzer over HTTP, masks detected entities, and walks JSON values.
// It only uses the standard library so it can be unit tested on its own.
package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Entity is one PII finding returned by Presidio's /analyze endpoint.
// Start and End are offsets in Unicode code points (Python string indices),
// not bytes.
type Entity struct {
	Type  string  `json:"entity_type"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Score float64 `json:"score"`
}

// Analyzer detects entities in a list of texts. The result has one entry per
// input text, in the same order.
type Analyzer interface {
	Analyze(ctx context.Context, texts []string) ([][]Entity, error)
}

// HTTPAnalyzer calls a Presidio analyzer service.
type HTTPAnalyzer struct {
	Client         *http.Client
	Endpoint       string // base URL, e.g. http://presidio-analyzer:3000
	Language       string
	Entities       []string
	ScoreThreshold float64
	AllowList      []string
	// BatchRequests sends many texts in one request ("text" as a JSON list).
	// Turn it off for analyzer images that only accept a single string.
	BatchRequests bool
	// MaxBatchSize caps the number of texts per request when batching.
	MaxBatchSize int
}

type analyzeRequest struct {
	Text           any      `json:"text"`
	Language       string   `json:"language"`
	Entities       []string `json:"entities,omitempty"`
	ScoreThreshold *float64 `json:"score_threshold,omitempty"`
	AllowList      []string `json:"allow_list,omitempty"`
}

// Analyze implements Analyzer.
func (a *HTTPAnalyzer) Analyze(ctx context.Context, texts []string) ([][]Entity, error) {
	out := make([][]Entity, 0, len(texts))
	if !a.BatchRequests {
		for _, t := range texts {
			var ents []Entity
			if err := a.post(ctx, a.request(t), &ents); err != nil {
				return nil, err
			}
			out = append(out, ents)
		}
		return out, nil
	}

	size := a.MaxBatchSize
	if size <= 0 {
		size = 100
	}
	for start := 0; start < len(texts); start += size {
		end := start + size
		if end > len(texts) {
			end = len(texts)
		}
		chunk := texts[start:end]
		var res [][]Entity
		if err := a.post(ctx, a.request(chunk), &res); err != nil {
			return nil, err
		}
		if len(res) != len(chunk) {
			return nil, fmt.Errorf("presidio analyzer returned %d results for %d texts", len(res), len(chunk))
		}
		out = append(out, res...)
	}
	return out, nil
}

func (a *HTTPAnalyzer) request(text any) analyzeRequest {
	req := analyzeRequest{
		Text:      text,
		Language:  a.Language,
		Entities:  a.Entities,
		AllowList: a.AllowList,
	}
	if a.ScoreThreshold > 0 {
		st := a.ScoreThreshold
		req.ScoreThreshold = &st
	}
	return req
}

// post sends one /analyze request. Errors never include request or response
// bodies, because those can contain the PII we are trying to remove.
func (a *HTTPAnalyzer) post(ctx context.Context, body analyzeRequest, out any) error {
	if a.Client == nil {
		return errors.New("presidio analyzer client not initialised")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode analyzer request: %w", err)
	}
	url := strings.TrimRight(a.Endpoint, "/") + "/analyze"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build analyzer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.Client.Do(req)
	if err != nil {
		return fmt.Errorf("call presidio analyzer: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("presidio analyzer returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode analyzer response: %w", err)
	}
	return nil
}
