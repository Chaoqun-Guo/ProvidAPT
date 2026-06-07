// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════
// Lexer
// ═══════════════════════════════════════════════════════════════

type tokenType int

const (
	tokEOF tokenType = iota
	tokMATCH
	tokWHERE
	tokDURING
	tokRETURN
	tokSTARTSWITH
	tokCONTAINS
	tokLPAREN    // (
	tokRPAREN    // )
	tokLBRACKET  // [
	tokRBRACKET  // ]
	tokCOLON     // :
	tokMINUS     // -
	tokRARROW    // ->
	tokCOMMA     // ,
	tokDOT       // .
	tokEQ        // =
	tokGT        // >
	tokLT        // <
	tokGTE       // >=
	tokLTE       // <=
	tokSTRING    // "..." or '...'
	tokIDENT     // identifier
	tokNUMBER    // number
)

type token struct {
	typ tokenType
	val string
	pos int
}

type lexer struct {
	input string
	pos   int
}

func newLexer(input string) *lexer {
	return &lexer{input: input}
}

func (l *lexer) peek() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *lexer) next() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	b := l.input[l.pos]
	l.pos++
	return b
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(rune(l.input[l.pos])) {
		l.pos++
	}
}

func (l *lexer) readWord() string {
	start := l.pos
	for l.pos < len(l.input) && (unicode.IsLetter(rune(l.input[l.pos])) || l.input[l.pos] == '_' || l.input[l.pos] == '*') {
		l.pos++
	}
	return l.input[start:l.pos]
}

func (l *lexer) readString(quote byte) (string, error) {
	l.pos++ // skip opening quote
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != quote {
		l.pos++
	}
	if l.pos >= len(l.input) {
		return "", fmt.Errorf("unterminated string at position %d", start)
	}
	val := l.input[start:l.pos]
	l.pos++ // skip closing quote
	return val, nil
}

func (l *lexer) nextToken() (token, error) {
	l.skipWhitespace()
	if l.pos >= len(l.input) {
		return token{typ: tokEOF, pos: l.pos}, nil
	}

	pos := l.pos
	ch := l.next()

	// Single-character tokens
	switch ch {
	case '(':
		return token{typ: tokLPAREN, val: "(", pos: pos}, nil
	case ')':
		return token{typ: tokRPAREN, val: ")", pos: pos}, nil
	case '[':
		return token{typ: tokLBRACKET, val: "[", pos: pos}, nil
	case ']':
		return token{typ: tokRBRACKET, val: "]", pos: pos}, nil
	case ':':
		return token{typ: tokCOLON, val: ":", pos: pos}, nil
	case ',':
		return token{typ: tokCOMMA, val: ",", pos: pos}, nil
	case '.':
		return token{typ: tokDOT, val: ".", pos: pos}, nil
	}

	// String literals
	if ch == '"' || ch == '\'' {
		l.pos-- // rewind to include opening quote in readString
		val, err := l.readString(ch)
		if err != nil {
			return token{}, err
		}
		return token{typ: tokSTRING, val: val, pos: pos}, nil
	}

	// Relations: -> (must check before bare '-')
	if ch == '-' && l.peek() == '>' {
		l.pos++
		return token{typ: tokRARROW, val: "->", pos: pos}, nil
	}

	// Single '-'
	if ch == '-' {
		return token{typ: tokMINUS, val: "-", pos: pos}, nil
	}

	// Numbers (ISO timestamps, etc.)
	if ch >= '0' && ch <= '9' {
		start := l.pos - 1
		// Read until whitespace or special char
		for l.pos < len(l.input) && !unicode.IsSpace(rune(l.input[l.pos])) &&
			l.input[l.pos] != ']' && l.input[l.pos] != ',' {
			l.pos++
		}
		return token{typ: tokSTRING, val: l.input[start:l.pos], pos: pos}, nil
	}

	// Operators: >=, <=
	if ch == '>' && l.peek() == '=' {
		l.pos++
		return token{typ: tokGTE, val: ">=", pos: pos}, nil
	}
	if ch == '<' && l.peek() == '=' {
		l.pos++
		return token{typ: tokLTE, val: "<=", pos: pos}, nil
	}
	if ch == '=' {
		return token{typ: tokEQ, val: "=", pos: pos}, nil
	}
	if ch == '>' {
		return token{typ: tokGT, val: ">", pos: pos}, nil
	}
	if ch == '<' {
		return token{typ: tokLT, val: "<", pos: pos}, nil
	}

	// Identifiers / keywords
	if unicode.IsLetter(rune(ch)) || ch == '_' {
		l.pos-- // rewind, readWord will advance
		word := l.readWord()
		up := strings.ToUpper(word)
		switch up {
		case "MATCH":
			return token{typ: tokMATCH, val: word, pos: pos}, nil
		case "WHERE":
			return token{typ: tokWHERE, val: word, pos: pos}, nil
		case "DURING":
			return token{typ: tokDURING, val: word, pos: pos}, nil
		case "RETURN":
			return token{typ: tokRETURN, val: word, pos: pos}, nil
		case "STARTSWITH":
			return token{typ: tokSTARTSWITH, val: word, pos: pos}, nil
		case "CONTAINS":
			return token{typ: tokCONTAINS, val: word, pos: pos}, nil
		default:
			return token{typ: tokIDENT, val: word, pos: pos}, nil
		}
	}

	return token{}, fmt.Errorf("unexpected character '%c' at position %d", ch, pos)
}

// ═══════════════════════════════════════════════════════════════
// Recursive descent parser
// ═══════════════════════════════════════════════════════════════

type parser struct {
	lexer  *lexer
	curr   token
	peek   token
	err    error
}

// Parse parses a ProvQL query string into an AST.
func Parse(input string) (*Query, error) {
	p := &parser{lexer: newLexer(input)}
	p.next() // prime the token stream
	return p.parseQuery()
}

func (p *parser) next() {
	p.curr = p.peek
	tok, err := p.lexer.nextToken()
	if err != nil {
		p.err = err
	}
	p.peek = tok
}

func (p *parser) expect(typ tokenType) (token, error) {
	if p.err != nil {
		return token{}, p.err
	}
	if p.peek.typ != typ {
		return token{}, fmt.Errorf("expected %s but got %s (%q) at position %d",
			tokenName(typ), tokenName(p.peek.typ), p.peek.val, p.peek.pos)
	}
	t := p.peek
	p.next()
	return t, nil
}

func (p *parser) parseQuery() (*Query, error) {
	q := &Query{}

	// MATCH
	if _, err := p.expect(tokMATCH); err != nil {
		return nil, err
	}
	path, err := p.parsePath()
	if err != nil {
		return nil, err
	}
	q.Match = path

	// WHERE (optional)
	if p.peek.typ == tokWHERE {
		p.next()
		conds, err := p.parseConditions()
		if err != nil {
			return nil, err
		}
		q.Where = conds
	}

	// DURING (optional)
	if p.peek.typ == tokDURING {
		p.next()
		tw, err := p.parseTimeWindow()
		if err != nil {
			return nil, err
		}
		q.During = tw
	}

	// RETURN
	if _, err := p.expect(tokRETURN); err != nil {
		return nil, err
	}
	proj, err := p.parseProjections()
	if err != nil {
		return nil, err
	}
	q.Return = proj

	return q, nil
}

// parsePath: (node) (edge node)*
func (p *parser) parsePath() (*PathPattern, error) {
	path := &PathPattern{}

	// Parse first node
	node, err := p.parseNode()
	if err != nil {
		return nil, err
	}
	path.Nodes = append(path.Nodes, node)

	// Parse edge-node pairs
	for p.peek.typ == tokMINUS {
		edge, err := p.parseEdge()
		if err != nil {
			return nil, err
		}
		path.Edges = append(path.Edges, edge)

		node, err := p.parseNode()
		if err != nil {
			return nil, err
		}
		path.Nodes = append(path.Nodes, node)
	}

	return path, nil
}

// parseNode: '(' IDENT ':' IDENT ')'
func (p *parser) parseNode() (NodePattern, error) {
	var n NodePattern

	if _, err := p.expect(tokLPAREN); err != nil {
		return n, err
	}

	// Variable
	t, err := p.expect(tokIDENT)
	if err != nil {
		return n, err
	}
	n.Variable = t.val

	// Colon
	if _, err := p.expect(tokCOLON); err != nil {
		return n, err
	}

	// Label
	t, err = p.expect(tokIDENT)
	if err != nil {
		return n, err
	}
	n.Label = t.val

	if _, err := p.expect(tokRPAREN); err != nil {
		return n, err
	}

	return n, nil
}

// parseEdge: - '[' ':' IDENT ']' '->'
func (p *parser) parseEdge() (EdgePattern, error) {
	var e EdgePattern

	if _, err := p.expect(tokMINUS); err != nil {
		return e, err
	}
	if _, err := p.expect(tokLBRACKET); err != nil {
		return e, err
	}
	if _, err := p.expect(tokCOLON); err != nil {
		return e, err
	}

	t, err := p.expect(tokIDENT)
	if err != nil {
		return e, err
	}
	e.Relation = strings.ToUpper(t.val)

	if _, err := p.expect(tokRBRACKET); err != nil {
		return e, err
	}
	if _, err := p.expect(tokRARROW); err != nil {
		return e, err
	}

	return e, nil
}

// parseConditions: field OP value (for simplicity, single condition)
func (p *parser) parseConditions() ([]Condition, error) {
	var conds []Condition

	// First condition: field
	t, err := p.expect(tokIDENT)
	if err != nil {
		return nil, err
	}
	field := t.val

	// Dot and subfield (e.g., f.path)
	if p.peek.typ == tokDOT {
		p.next()
		t, err := p.expect(tokIDENT)
		if err != nil {
			return nil, err
		}
		field = field + "." + t.val
	}

	// Operator
	var op Op
	switch p.peek.typ {
	case tokEQ:
		op = OpEQ
	case tokSTARTSWITH:
		op = OpSTARTSWITH
	case tokCONTAINS:
		op = OpCONTAINS
	case tokGT:
		op = OpGT
	case tokLT:
		op = OpLT
	case tokGTE:
		op = OpGTE
	case tokLTE:
		op = OpLTE
	default:
		return nil, fmt.Errorf("expected operator, got %s", tokenName(p.peek.typ))
	}
	p.next()

	// Value
	t, err = p.expect(tokSTRING)
	if err != nil {
		return nil, err
	}
	conds = append(conds, Condition{
		Field: field, Op: op, Value: t.val,
	})

	return conds, nil
}

// parseTimeWindow: '[' STRING ',' STRING ']'
func (p *parser) parseTimeWindow() (*TimeWindow, error) {
	if _, err := p.expect(tokLBRACKET); err != nil {
		return nil, err
	}
	t1, err := p.expect(tokSTRING)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tokCOMMA); err != nil {
		return nil, err
	}
	t2, err := p.expect(tokSTRING)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tokRBRACKET); err != nil {
		return nil, err
	}

	start, err := time.Parse(time.RFC3339Nano, t1.val)
	if err != nil {
		start, err = time.Parse(time.RFC3339, t1.val)
		if err != nil {
			return nil, fmt.Errorf("parse time %q: %w", t1.val, err)
		}
	}
	end, err := time.Parse(time.RFC3339Nano, t2.val)
	if err != nil {
		end, err = time.Parse(time.RFC3339, t2.val)
		if err != nil {
			return nil, fmt.Errorf("parse time %q: %w", t2.val, err)
		}
	}

	return &TimeWindow{Start: start, End: end}, nil
}

// parseProjections: IDENT ('.' IDENT)? (',' ...)*
func (p *parser) parseProjections() ([]Projection, error) {
	var projs []Projection

	for {
		t, err := p.expect(tokIDENT)
		if err != nil {
			return nil, err
		}
		proj := Projection{Variable: t.val}

		if p.peek.typ == tokDOT {
			p.next()
			t, err := p.expect(tokIDENT)
			if err != nil {
				return nil, err
			}
			proj.Field = t.val
		}

		projs = append(projs, proj)

		if p.peek.typ != tokCOMMA {
			break
		}
		p.next()
	}

	return projs, nil
}

func tokenName(t tokenType) string {
	switch t {
	case tokEOF:
		return "EOF"
	case tokMATCH:
		return "MATCH"
	case tokWHERE:
		return "WHERE"
	case tokDURING:
		return "DURING"
	case tokRETURN:
		return "RETURN"
	case tokSTARTSWITH:
		return "STARTSWITH"
	case tokCONTAINS:
		return "CONTAINS"
	case tokLPAREN:
		return "'('"
	case tokRPAREN:
		return "')'"
	case tokLBRACKET:
		return "'['"
	case tokRBRACKET:
		return "']'"
	case tokCOLON:
		return "':'"
	case tokRARROW:
		return "'->'"
	case tokCOMMA:
		return "','"
	case tokDOT:
		return "'.'"
	case tokEQ:
		return "'='"
	case tokSTRING:
		return "string"
	case tokIDENT:
		return "identifier"
	case tokMINUS:
		return "'-'"
	case tokGT:
		return "'>'"
	case tokLT:
		return "'<'"
	case tokGTE:
		return "'>='"
	case tokLTE:
		return "'<='"
	default:
		return fmt.Sprintf("token(%d)", t)
	}
}
