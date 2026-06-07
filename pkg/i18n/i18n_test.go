package i18n

import (
	"testing"
)

func TestDefaultLocale(t *testing.T) {
	if Locale() != "en" {
		t.Errorf("default locale = %q, want en", Locale())
	}
}

func TestSetLocale(t *testing.T) {
	SetLocale("zh")
	if Locale() != "zh" {
		t.Errorf("locale = %q, want zh", Locale())
	}

	SetLocale("en")
	if Locale() != "en" {
		t.Errorf("locale = %q, want en", Locale())
	}
}

func TestT(t *testing.T) {
	SetLocale("en")
	if s := T("daemon_starting"); s != "ProvidAPT daemon starting" {
		t.Errorf("T(daemon_starting) = %q", s)
	}

	SetLocale("zh")
	if s := T("daemon_starting"); s != "ProvidAPT 守护进程正在启动" {
		t.Errorf("T(daemon_starting) = %q", s)
	}

	SetLocale("en")
	if s := T("nonexistent_key"); s != "nonexistent_key" {
		t.Errorf("T(nonexistent) = %q, want the key itself", s)
	}
}

func TestTargs(t *testing.T) {
	SetLocale("en")
	if s := Targs("daemon_started", 1234); s != "ProvidAPT daemon started (PID 1234)" {
		t.Errorf("Targs = %q", s)
	}
}

func TestFmtString(t *testing.T) {
	tests := []struct {
		format string
		args   []interface{}
		want   string
	}{
		{"PID %d", []interface{}{42}, "PID 42"},
		{"path: %s", []interface{}{"/etc/hosts"}, "path: /etc/hosts"},
		{"val: %v", []interface{}{"test"}, "val: test"},
		{"rate: %.1f req/s", []interface{}{float64(100.5)}, "rate: 100.5 req/s"},
		{"no args", nil, "no args"},
	}
	for _, tt := range tests {
		got := fmtString(tt.format, tt.args...)
		if got != tt.want {
			t.Errorf("fmtString(%q, %v) = %q, want %q", tt.format, tt.args, got, tt.want)
		}
	}
}

func TestInitFromEnv(t *testing.T) {
	t.Setenv("PROVIDAPT_LOCALE", "zh")
	InitFromEnv()
	if Locale() != "zh" {
		t.Errorf("after InitFromEnv, locale = %q", Locale())
	}
}
