package redact

import "strings"

// KeyMatcher decides which attribute keys are scanned.
// A pattern is either an exact key ("gen_ai.input.messages"), a prefix ending
// in "*" ("llm.input_messages.*" matches "llm.input_messages.0.message.content"),
// or "*" on its own to scan every key.
type KeyMatcher struct {
	all      bool
	exact    map[string]struct{}
	prefixes []string
}

// NewKeyMatcher builds a matcher from config patterns.
func NewKeyMatcher(patterns []string) KeyMatcher {
	km := KeyMatcher{exact: make(map[string]struct{}, len(patterns))}
	for _, p := range patterns {
		switch {
		case p == "*":
			km.all = true
		case strings.HasSuffix(p, "*"):
			km.prefixes = append(km.prefixes, strings.TrimSuffix(p, "*"))
		case p != "":
			km.exact[p] = struct{}{}
		}
	}
	return km
}

// Match reports whether key should be scanned.
func (k KeyMatcher) Match(key string) bool {
	if k.all {
		return true
	}
	if _, ok := k.exact[key]; ok {
		return true
	}
	for _, p := range k.prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}
