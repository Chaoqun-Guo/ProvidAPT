package clioutput

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// Table renders aligned columns to stdout (like docker ps).
// In JSON mode Render is a no-op.
type Table struct {
	headers []string
	rows    [][]string
}

// NewTable creates a Table with the given column headers.
func NewTable(headers ...string) *Table {
	return &Table{headers: headers}
}

// AddRow appends a data row. Columns beyond len(headers) are silently
// dropped; fewer columns leave trailing cells empty.
func (t *Table) AddRow(cols ...string) {
	if len(cols) > len(t.headers) {
		cols = cols[:len(t.headers)]
	}
	t.rows = append(t.rows, cols)
}

// Render writes the table via tabwriter for perfect column alignment.
// No-op in JSON mode.
func (t *Table) Render() {
	if jsonMode {
		return
	}
	if len(t.headers) == 0 {
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 4, 0, 3, ' ', tabwriter.StripEscape)

	// Header row
	for i, h := range t.headers {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, Bold(h))
	}
	fmt.Fprintln(w)

	// Separator row (— repeated to header width)
	for i, h := range t.headers {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, strings.Repeat("—", len(h)))
	}
	fmt.Fprintln(w)

	// Data rows
	for _, row := range t.rows {
		for i, col := range row {
			if i > 0 {
				fmt.Fprint(w, "\t")
			}
			fmt.Fprint(w, col)
		}
		// Pad missing columns
		for i := len(row); i < len(t.headers); i++ {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprintln(w)
	}

	_ = w.Flush()
}
