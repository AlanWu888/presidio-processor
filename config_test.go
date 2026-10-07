package presidioprocessor

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/confmap/confmaptest"
)

func TestLoadConfig(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := cm.Sub("presidio")
	if err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	if err := sub.Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config: %v", err)
	}

	if cfg.Analyzer.Endpoint != "http://presidio-analyzer:3000" || cfg.Analyzer.Timeout != 3*time.Second {
		t.Errorf("http client settings not loaded: %+v", cfg.Analyzer.ClientConfig)
	}
	if cfg.Analyzer.ScoreThreshold != 0.6 || len(cfg.Analyzer.Entities) != 3 || cfg.Analyzer.AllowList[0] != "Acme Ltd" {
		t.Errorf("analyzer settings not loaded: %+v", cfg.Analyzer)
	}
	if len(cfg.Attributes) != 2 || cfg.Operator != "hash" || string(cfg.HashKey) != "test-key" || cfg.OnError != OnErrorReject {
		t.Errorf("processor settings not loaded: %+v", cfg)
	}
	// Unset fields keep their defaults.
	if !cfg.JSONAware || !cfg.ScanSpanEvents || !cfg.Analyzer.BatchRequests {
		t.Errorf("defaults lost: %+v", cfg)
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	if err := createDefaultConfig().(*Config).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsBadConfig(t *testing.T) {
	cases := map[string]func(*Config){
		"analyzer.endpoint": func(c *Config) { c.Analyzer.Endpoint = "" },
		"score_threshold":   func(c *Config) { c.Analyzer.ScoreThreshold = 2 },
		"hash_key":          func(c *Config) { c.Operator = "hash" },
		"operator":          func(c *Config) { c.Operator = "encrypt" },
		"on_error":          func(c *Config) { c.OnError = "ignore" },
		"nothing to scan":   func(c *Config) { c.Attributes = nil; c.ScanLogBody = false },
	}
	for want, mutate := range cases {
		cfg := createDefaultConfig().(*Config)
		mutate(cfg)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expected error mentioning %q, got %v", want, err)
		}
	}
}
