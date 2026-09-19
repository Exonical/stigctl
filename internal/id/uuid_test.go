package id

import (
	"regexp"
	"testing"
)

func TestUUIDv4(t *testing.T) {
	got, err := UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(got) {
		t.Fatalf("UUIDv4() = %q", got)
	}
}
