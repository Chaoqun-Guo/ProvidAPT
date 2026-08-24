package i18n

import (
	"strconv"
	"strings"
)

// fmtString is a minimal fmt.Sprintf replacement that avoids importing
// the full fmt package. Supports %d, %s, %v, %.Nf with width/precision.
func fmtString(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}

	var buf strings.Builder
	argIdx := 0

	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			buf.WriteByte(format[i])
			continue
		}
		i++ // skip '%'

		// %% → literal %
		if i < len(format) && format[i] == '%' {
			buf.WriteByte('%')
			continue
		}

		if argIdx >= len(args) {
			buf.WriteByte('%')
			continue
		}

		// Skip optional flags: -+0 #, width digits, and .precision
		for i < len(format) && isFlag(format[i]) {
			i++
		}
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
		prec := -1
		if i < len(format) && format[i] == '.' {
			i++ // skip '.'
			precStart := i
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
			if precStart < i {
				prec, _ = strconv.Atoi(format[precStart:i])
			}
		}

		if i >= len(format) {
			buf.WriteByte('%')
			break
		}

		verb := format[i]
		switch verb {
		case 'd':
			switch v := args[argIdx].(type) {
			case int:
				buf.WriteString(strconv.Itoa(v))
			case int64:
				buf.WriteString(strconv.FormatInt(v, 10))
			case uint:
				buf.WriteString(strconv.FormatUint(uint64(v), 10))
			case uint32:
				buf.WriteString(strconv.FormatUint(uint64(v), 10))
			case uint64:
				buf.WriteString(strconv.FormatUint(v, 10))
			default:
				if i, ok := v.(int); ok {
					buf.WriteString(strconv.Itoa(i))
				} else {
					buf.WriteString("?")
				}
			}
			argIdx++
		case 's':
			if s, ok := args[argIdx].(string); ok {
				buf.WriteString(s)
			} else {
				buf.WriteString("?")
			}
			argIdx++
		case 'v':
			buf.WriteString(fmtV(args[argIdx]))
			argIdx++
		case 'f':
			switch v := args[argIdx].(type) {
			case float64:
				buf.WriteString(strconv.FormatFloat(v, 'f', prec, 64))
			case float32:
				buf.WriteString(strconv.FormatFloat(float64(v), 'f', prec, 32))
			default:
				if f, ok := v.(float64); ok {
					buf.WriteString(strconv.FormatFloat(f, 'f', prec, 64))
				} else {
					buf.WriteString("?")
				}
			}
			argIdx++
		default:
			buf.WriteByte('%')
			buf.WriteByte(verb)
		}
	}

	return buf.String()
}

func isFlag(c byte) bool {
	return c == '-' || c == '+' || c == ' ' || c == '0' || c == '#'
}

func fmtV(v interface{}) string {
	if v == nil {
		return "<nil>"
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case bool:
		return strconv.FormatBool(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case error:
		return val.Error()
	default:
		return "?"
	}
}
