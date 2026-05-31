// Package cli implements the ProvidAPT CLI query DSL.
//
// Syntax:
//   find <type> [where <field>=<value>]
//     [-> follow <direction>]
//     [-> <relation>]
//     [-> find <type> [where ...]]
//
// Examples:
//   find process where name="nginx" -> follow child -> find file where path="/etc/*"
//   find process where pid=100 -> write -> find file
//   find network where addr="5.6.7.8" -> follow parent -> find process
package dsl

import (
	"fmt"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════
// Tokenizer
// ═══════════════════════════════════════════════════════════════

type tokenType int

const (
	tokEOF tokenType = iota
	tokFind
	tokFollow
	tokWhere
	tokArrow     // ->
	tokProcess
	tokFile
	tokNetwork
	tokChild
	tokParent
	tokRead
	tokWrite
	tokConnect
	tokFork
	tokEq        // =
	tokString    // "..." or unquoted
	tokNumber
	tokIdent
)

type token struct {
	typ tokenType
	val string
}

type lexer struct {
	input []string
	pos   int
}

func newLexer(input string) *lexer {
	// Split on whitespace but keep quoted strings
	parts := tokenize(input)
	return &lexer{input: parts}
}

func tokenize(input string) []string {
	var parts []string
	var current []rune
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(input); i++ {
		c := input[i]
		if inQuote {
			current = append(current, rune(c))
			if c == quoteChar {
				inQuote = false
			}
			continue
		}
		switch {
		case c == '"' || c == '\'':
			if len(current) > 0 {
				parts = append(parts, string(current))
				current = nil
			}
			current = append(current, rune(c))
			inQuote = true
			quoteChar = c
		case c == ' ' || c == '\t':
			if len(current) > 0 {
				parts = append(parts, string(current))
				current = nil
			}
		case c == '=':
			if len(current) > 0 {
				parts = append(parts, string(current))
				current = nil
			}
			parts = append(parts, "=")
		case c == '-' && i+1 < len(input) && input[i+1] == '>':
			if len(current) > 0 {
				parts = append(parts, string(current))
				current = nil
			}
			parts = append(parts, "->")
			i++
		default:
			current = append(current, rune(c))
		}
	}
	if len(current) > 0 {
		parts = append(parts, string(current))
	}
	return parts
}

func (l *lexer) next() token {
	if l.pos >= len(l.input) {
		return token{typ: tokEOF}
	}
	word := l.input[l.pos]
	l.pos++

	switch strings.ToLower(word) {
	case "find":
		return token{typ: tokFind, val: word}
	case "follow":
		return token{typ: tokFollow, val: word}
	case "where":
		return token{typ: tokWhere, val: word}
	case "->":
		return token{typ: tokArrow, val: word}
	case "process":
		return token{typ: tokProcess, val: word}
	case "file":
		return token{typ: tokFile, val: word}
	case "network":
		return token{typ: tokNetwork, val: word}
	case "child":
		return token{typ: tokChild, val: word}
	case "parent":
		return token{typ: tokParent, val: word}
	case "read":
		return token{typ: tokRead, val: word}
	case "write":
		return token{typ: tokWrite, val: word}
	case "connect":
		return token{typ: tokConnect, val: word}
	case "fork":
		return token{typ: tokFork, val: word}
	case "=":
		return token{typ: tokEq, val: word}
	}

	// Numbers
	if isNumeric(word) {
		return token{typ: tokNumber, val: word}
	}

	// String (strip quotes)
	if (word[0] == '"' && word[len(word)-1] == '"') ||
		(word[0] == '\'' && word[len(word)-1] == '\'') {
		return token{typ: tokString, val: word[1 : len(word)-1]}
	}

	return token{typ: tokIdent, val: word}
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// ═══════════════════════════════════════════════════════════════
// AST
// ═══════════════════════════════════════════════════════════════

// QueryStep is one step in a chain query.
type QueryStep struct {
	Action    string // "find", "follow"
	NodeType  string // "process", "file", "network"
	Direction string // "child", "parent" (for follow)
	Relation  string // "read", "write", "connect", "fork" (edge filter)
	Field     string // field name for where clause
	Value     string // field value for where clause
}

// Query is a parsed chain query.
type Query struct {
	Steps []QueryStep
}

// Parse parses a DSL query string.
func Parse(input string) (*Query, error) {
	l := newLexer(input)
	q := &Query{}

	for {
		tok := l.next()
		switch tok.typ {
		case tokEOF:
			if len(q.Steps) == 0 {
				return nil, fmt.Errorf("empty query")
			}
			return q, nil
		case tokFind:
			step, err := parseFind(l)
			if err != nil {
				return nil, err
			}
			q.Steps = append(q.Steps, step)
		case tokArrow:
			// Parse arrow + following token
			next := l.next()
			switch next.typ {
			case tokFollow:
				dir := l.next()
				if dir.typ != tokChild && dir.typ != tokParent {
					return nil, fmt.Errorf("expected child/parent after follow, got %s", dir.val)
				}
				dirName := "child"
				if dir.typ == tokParent {
					dirName = "parent"
				}
				q.Steps = append(q.Steps, QueryStep{
					Action:    "follow",
					Direction: dirName,
				})
			case tokRead, tokWrite, tokConnect, tokFork:
				q.Steps = append(q.Steps, QueryStep{
					Action:   "edge",
					Relation: next.val,
				})
			case tokFind:
				step, err := parseFind(l)
				if err != nil {
					return nil, err
				}
				q.Steps = append(q.Steps, step)
			default:
				return nil, fmt.Errorf("unexpected token after ->: %s", next.val)
			}
		default:
			return nil, fmt.Errorf("unexpected token: %s", tok.val)
		}
	}
}

func parseFind(l *lexer) (QueryStep, error) {
	step := QueryStep{Action: "find"}

	// Node type
	nt := l.next()
	switch nt.typ {
	case tokProcess:
		step.NodeType = "process"
	case tokFile:
		step.NodeType = "file"
	case tokNetwork:
		step.NodeType = "network"
	default:
		return step, fmt.Errorf("expected node type (process/file/network), got %s", nt.val)
	}

	// Optional where clause
	where := l.next()
	if where.typ == tokWhere {
		field := l.next()
		if field.typ != tokIdent {
			return step, fmt.Errorf("expected field name after where")
		}
		step.Field = field.val

		eq := l.next()
		if eq.typ != tokEq {
			return step, fmt.Errorf("expected = after field name")
		}
		_ = eq

		val := l.next()
		if val.typ != tokString && val.typ != tokNumber && val.typ != tokIdent {
			return step, fmt.Errorf("expected value after =")
		}
		step.Value = val.val
	} else {
		// Put back the token (not a where clause)
		l.pos-- // simple unget
	}

	return step, nil
}

// String returns a human-readable representation of the query.
func (q *Query) String() string {
	var parts []string
	for _, s := range q.Steps {
		switch s.Action {
		case "find":
			p := fmt.Sprintf("find %s", s.NodeType)
			if s.Field != "" {
				p += fmt.Sprintf(" where %s=%q", s.Field, s.Value)
			}
			parts = append(parts, p)
		case "follow":
			parts = append(parts, fmt.Sprintf("follow %s", s.Direction))
		case "edge":
			parts = append(parts, s.Relation)
		}
	}
	return strings.Join(parts, " -> ")
}
