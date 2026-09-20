package goss

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatMatcherValue(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		got := formatMatcherValue("evidence=ok\n")
		if got != "evidence=ok" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "evidence=ok")
		}
	})

	t.Run("bytes", func(t *testing.T) {
		got := formatMatcherValue([]byte("evidence=ok\n"))
		if got != "evidence=ok" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "evidence=ok")
		}
	})

	t.Run("advanced reader", func(t *testing.T) {
		reader := bytes.NewReader([]byte("evidence=permissive=missing last_rule=deny perm=any all : all\n"))
		if _, err := reader.Seek(0, 2); err != nil {
			t.Fatal(err)
		}

		got := formatMatcherValue(reader)
		want := "evidence=permissive=missing last_rule=deny perm=any all : all"
		if got != want {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, want)
		}
	})

	t.Run("ordinary scalar", func(t *testing.T) {
		got := formatMatcherValue(1)
		if got != "1" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "1")
		}
	})

	t.Run("buffer", func(t *testing.T) {
		got := formatMatcherValue(bytes.NewBufferString("line one\n"))
		if got != "line one" {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, "line one")
		}
	})

	t.Run("multiline preserves content", func(t *testing.T) {
		got := formatMatcherValue(strings.NewReader("line one\nline two\n"))
		want := "line one\nline two"
		if got != want {
			t.Fatalf("formatMatcherValue() = %q, want %q", got, want)
		}
	})
}
