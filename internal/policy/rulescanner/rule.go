// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

// Package detect implements a streaming detection engine for
// ProvidAPT v2.  It supports YAML-based custom detection rules
// (Sigma-inspired) and real-time graph scanning.
package rulescanner

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	pb "github.com/Chaoqun-Guo/ProvidAPT/pkg/api/proto/core"
)

// compiledRE caches compiled regex patterns for efficiency.
var compiledRE = make(map[string]*regexp.Regexp)

// ═══════════════════════════════════════════════════════════════
// YAML Rule Definition
// ═══════════════════════════════════════════════════════════════

// Rule is a single detection rule (Sigma-inspired format).
type Rule struct {
	Title       string    `yaml:"title"`
	ID          string    `yaml:"id"`
	Description string    `yaml:"description"`
	Author      string    `yaml:"author,omitempty"`
	Date        string    `yaml:"date,omitempty"`
	Level       string    `yaml:"level"` // low, medium, high, critical
	Tags        []string  `yaml:"tags,omitempty"`
	Detection   Detection `yaml:"detection"`
}

// Detection contains the selection criteria.
// Supports two formats:
//
// (a) Single inline selection (backward compatible with all existing rules):
//
//	detection:
//	  EventType: [10]
//	  TargetPath: /etc/shadow
//
// (b) Named selections — multiple named groups, each with its own AND-conditions.
//
//	    The "condition" field is a boolean expression (AND, OR, NOT, parentheses)
//	    over the named selections.
//
//		detection:
//		  sel1:
//		    EventType: [10]
//		  sel2:
//		    TargetPath: /etc/shadow
//		  condition: sel1 AND sel2
type Detection struct {
	// Selection is the single inline selection (backward compatible).
	Selection Selection `yaml:",inline"`
	// NamedSelections holds named selection groups for multi-selection rules.
	NamedSelections map[string]Selection `yaml:"selections,flow,omitempty"`
	// Condition is a boolean expression over selection names, e.g. "sel1 AND NOT sel2".
	// If empty, all populated selections are ANDed together.
	Condition string `yaml:"condition"`
}

// Selection is a set of AND-conditions.
type Selection struct {
	// EventType matches event type IDs (e.g., [10, 11]).
	EventType []uint32 `yaml:"EventType,omitempty"`

	// TargetPath matches file path patterns.
	TargetPath string `yaml:"TargetPath,omitempty"`

	// Comm matches process name.
	Comm string `yaml:"Comm,omitempty"`

	// UID matches user ID ("0", "!=0", ">1000").
	UID string `yaml:"UID,omitempty"`

	// PID matches process ID.
	PID string `yaml:"PID,omitempty"`

	// TargetIP matches destination IP.
	TargetIP string `yaml:"TargetIP,omitempty"`

	// TargetPort matches destination port.
	TargetPort string `yaml:"TargetPort,omitempty"`

	// Flags matches event flags (e.g., "setuid").
	Flags string `yaml:"Flags,omitempty"`
}

// ─── Rule loading ───────────────────────────────────────────

// LoadRule parses a single YAML rule.
func LoadRule(data []byte) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parse rule: %w", err)
	}
	if rule.Title == "" {
		return nil, fmt.Errorf("rule missing title")
	}
	if rule.Level == "" {
		rule.Level = "medium"
	}
	return &rule, nil
}

// LoadRuleFile loads a rule from a YAML file.
func LoadRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule file: %w", err)
	}
	return LoadRule(data)
}

// LoadAllRules loads all .yaml files from a directory.
func LoadAllRules(dir string) ([]*Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var rules []*Rule
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		path := dir + "/" + e.Name()
		rule, err := LoadRuleFile(path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", e.Name(), err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ─── Matching ───────────────────────────────────────────────

// Match checks if an event matches this rule's detection criteria.
// If a Condition is specified, it is evaluated as a boolean expression
// (AND, OR, NOT, parentheses) over the selection names.
// Without a Condition, all populated selections are ANDed together.
func (r *Rule) Match(evt *pb.Event) bool {
	results := make(map[string]bool)

	// Evaluate inline selection (backward compatible).
	if hasSelectionFields(r.Detection.Selection) {
		results["selection"] = r.matchSelection(r.Detection.Selection, evt)
	}

	// Evaluate named selections.
	for name, sel := range r.Detection.NamedSelections {
		results[name] = r.matchSelection(sel, evt)
	}

	if len(results) == 0 {
		return true // no selection criteria → matches everything
	}

	if r.Detection.Condition != "" {
		return evaluateCondition(r.Detection.Condition, results)
	}

	// Default: AND all selections.
	for _, v := range results {
		if !v {
			return false
		}
	}
	return true
}

// hasSelectionFields reports whether a Selection has any non-zero field.
func hasSelectionFields(s Selection) bool {
	return len(s.EventType) > 0 || s.TargetPath != "" || s.Comm != "" ||
		s.UID != "" || s.PID != "" || s.TargetIP != "" ||
		s.TargetPort != "" || s.Flags != ""
}

// ═══════════════════════════════════════════════════════════════
// Condition expression parser
// ═══════════════════════════════════════════════════════════════

// evaluateCondition evaluates a boolean expression over named selection results.
//
// Grammar (precedence: NOT > AND > OR):
//
//	expr      := term (OR term)*
//	term      := factor (AND factor)*
//	factor    := NOT factor | primary
//	primary   := IDENTIFIER | LPAREN expr RPAREN
//
// Selection names are case-sensitive; operators AND, OR, NOT are case-insensitive.
func evaluateCondition(cond string, results map[string]bool) bool {
	tokens := tokenizeCondition(cond)
	p := &condParser{tokens: tokens, results: results}
	return p.parseExpr()
}

// condTokenType enumerates condition token types.
type condTokenType int

const (
	tokIdent condTokenType = iota
	tokAND
	tokOR
	tokNOT
	tokLParen
	tokRParen
	tokEOF
)

// condToken is a single token from the condition string.
type condToken struct {
	typ condTokenType
	val string
}

func tokenizeCondition(cond string) []condToken {
	var tokens []condToken
	i := 0
	runes := []rune(cond)
	for i < len(runes) {
		ch := runes[i]
		if ch == ' ' || ch == '\t' {
			i++
			continue
		}
		if ch == '(' {
			tokens = append(tokens, condToken{typ: tokLParen, val: "("})
			i++
			continue
		}
		if ch == ')' {
			tokens = append(tokens, condToken{typ: tokRParen, val: ")"})
			i++
			continue
		}
		// Read a word (identifier or operator).
		start := i
		for i < len(runes) && runes[i] != ' ' && runes[i] != '\t' &&
			runes[i] != '(' && runes[i] != ')' {
			i++
		}
		word := string(runes[start:i])
		switch strings.ToUpper(word) {
		case "AND":
			tokens = append(tokens, condToken{typ: tokAND, val: word})
		case "OR":
			tokens = append(tokens, condToken{typ: tokOR, val: word})
		case "NOT":
			tokens = append(tokens, condToken{typ: tokNOT, val: word})
		default:
			tokens = append(tokens, condToken{typ: tokIdent, val: word})
		}
	}
	tokens = append(tokens, condToken{typ: tokEOF})
	return tokens
}

// condParser is a recursive-descent parser for condition expressions.
type condParser struct {
	tokens  []condToken
	pos     int
	results map[string]bool
}

func (p *condParser) peek() condToken {
	if p.pos >= len(p.tokens) {
		return condToken{typ: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *condParser) advance() {
	p.pos++
}

// expr   := term (OR term)*
func (p *condParser) parseExpr() bool {
	result := p.parseTerm()
	for p.peek().typ == tokOR {
		p.advance()
		right := p.parseTerm()
		result = result || right
	}
	return result
}

// term   := factor (AND factor)*
func (p *condParser) parseTerm() bool {
	result := p.parseFactor()
	for p.peek().typ == tokAND {
		p.advance()
		right := p.parseFactor()
		result = result && right
	}
	return result
}

// factor := NOT factor | primary
func (p *condParser) parseFactor() bool {
	if p.peek().typ == tokNOT {
		p.advance()
		return !p.parseFactor()
	}
	return p.parsePrimary()
}

// primary := IDENTIFIER | LPAREN expr RPAREN
func (p *condParser) parsePrimary() bool {
	tok := p.peek()
	switch tok.typ {
	case tokIdent:
		p.advance()
		if v, ok := p.results[tok.val]; ok {
			return v
		}
		return false // unknown selection → false (no match)
	case tokLParen:
		p.advance()
		result := p.parseExpr()
		// Expect closing paren — skip on mismatch (graceful degradation).
		if p.peek().typ == tokRParen {
			p.advance()
		}
		return result
	default:
		// Unexpected token → false (skip it).
		if p.peek().typ != tokEOF {
			p.advance()
		}
		return false
	}
}

// matchSelection checks if an event matches a single selection (AND logic).
func (r *Rule) matchSelection(sel Selection, evt *pb.Event) bool {
	// EventType check
	if len(sel.EventType) > 0 {
		found := false
		for _, et := range sel.EventType {
			if evt.Type == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// TargetPath check (file path)
	if sel.TargetPath != "" {
		if !patternMatch(sel.TargetPath, evt.Pathname) {
			return false
		}
	}

	// Comm check (process name)
	if sel.Comm != "" {
		if !patternMatch(sel.Comm, evt.Comm) {
			return false
		}
	}

	// UID check
	if sel.UID != "" {
		if !compareField(sel.UID, uint64(evt.Uid)) {
			return false
		}
	}

	// PID check
	if sel.PID != "" {
		if !compareField(sel.PID, uint64(evt.Pid)) {
			return false
		}
	}

	// TargetPort check
	if sel.TargetPort != "" {
		if !compareField(sel.TargetPort, uint64(evt.Dport)) {
			return false
		}
	}

	// TargetIP check
	if sel.TargetIP != "" {
		ipStr := intToIP(evt.Daddr)
		if !patternMatch(sel.TargetIP, ipStr) {
			return false
		}
	}

	// Flags check (e.g., "setuid")
	if sel.Flags != "" {
		if sel.Flags == "setuid" && evt.Flags&1 == 0 {
			return false
		}
	}

	return true
}

// ─── Field comparison ───────────────────────────────────────

// compareField compares a field string with a value.
// Supports: "1000", "!=0", ">1000", "<100", ">=5", "<=10".
func compareField(field string, value uint64) bool {
	field = strings.TrimSpace(field)

	parseCmp := func(raw string) (uint64, bool) {
		var cmp uint64
		if _, err := fmt.Sscanf(raw, "%d", &cmp); err != nil {
			return 0, false
		}
		return cmp, true
	}

	switch {
	case strings.HasPrefix(field, "!="):
		cmp, ok := parseCmp(field[2:])
		if !ok {
			return false
		}
		return value != cmp

	case strings.HasPrefix(field, ">="):
		cmp, ok := parseCmp(field[2:])
		if !ok {
			return false
		}
		return value >= cmp

	case strings.HasPrefix(field, "<="):
		cmp, ok := parseCmp(field[2:])
		if !ok {
			return false
		}
		return value <= cmp

	case strings.HasPrefix(field, ">"):
		cmp, ok := parseCmp(field[1:])
		if !ok {
			return false
		}
		return value > cmp

	case strings.HasPrefix(field, "<"):
		cmp, ok := parseCmp(field[1:])
		if !ok {
			return false
		}
		return value < cmp

	default:
		cmp, ok := parseCmp(field)
		if !ok {
			return false
		}
		return value == cmp
	}
}

// ─── Pattern matching ───────────────────────────────────────

// patternMatch supports:
//   - Exact match: "pattern"
//   - Prefix wildcard: "prefix*"
//   - Suffix wildcard: "*suffix"
//   - Regex pattern: "/regex/"
func patternMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}

	// Regex pattern: /pattern/ (starts and ends with /, not a filesystem path)
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") &&
		len(pattern) > 2 && !strings.Contains(pattern[1:len(pattern)-1], "/") {
		expr := pattern[1 : len(pattern)-1]
		re, ok := compiledRE[pattern]
		if !ok {
			var err error
			re, err = regexp.Compile(expr)
			if err != nil {
				return false // invalid regex = no match
			}
			compiledRE[pattern] = re
		}
		return re.MatchString(value)
	}

	// Prefix wildcard: "prefix*"
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}

	// Suffix wildcard: "*suffix"
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix
	}

	return pattern == value
}

// ─── Helpers ────────────────────────────────────────────────

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}
