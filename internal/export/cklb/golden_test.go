package cklb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	stigexport "github.com/Exonical/stigctl/internal/export"
	"github.com/Exonical/stigctl/internal/xccdf"
)

const (
	rhel9V2R9GoldenCKLBSourceSHA256 = "a9f65d3b0120abdb210375009a813dedb0f5e51bf9ce806a171bac74d1f13a9a"
	rhel9V2R9GoldenDocumentSHA256   = "df35c4e082755c56e45838fa804e1d6fc19203df8dc829ee5a84df13b6cd7448"
)

func TestRHEL9V2R9GoldenCKLB(t *testing.T) {
	xccdfPath := os.Getenv("STIGCTL_GOLDEN_XCCDF")
	if xccdfPath == "" {
		t.Skip("set STIGCTL_GOLDEN_XCCDF to the official RHEL 9 V2R9 XCCDF to run the golden CKLB compatibility test")
	}

	source, err := os.Open(xccdfPath)
	if err != nil {
		t.Fatalf("open XCCDF: %v", err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Errorf("close XCCDF: %v", err)
		}
	}()

	benchmark, err := xccdf.Parse(source)
	if err != nil {
		t.Fatalf("parse XCCDF: %v", err)
	}
	if benchmark.ID != "RHEL_9_STIG" {
		t.Fatalf("benchmark ID = %q", benchmark.ID)
	}
	if benchmark.Version != "2" {
		t.Fatalf("benchmark version = %q", benchmark.Version)
	}
	if benchmark.ReleaseInfo != "Release: 9 Benchmark Date: 01 Jul 2026" {
		t.Fatalf("release_info = %q", benchmark.ReleaseInfo)
	}
	if len(benchmark.Rules) != 445 {
		t.Fatalf("rule count = %d, want 445", len(benchmark.Rules))
	}

	var buf bytes.Buffer
	if err := (Exporter{}).Export(context.Background(), &buf, stigexport.Request{
		Baseline:  "RHEL_9_Dev",
		Benchmark: benchmark,
	}); err != nil {
		t.Fatalf("export CKLB: %v", err)
	}

	if output := os.Getenv("STIGCTL_GOLDEN_OUTPUT"); output != "" {
		if err := os.WriteFile(output, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("write generated CKLB: %v", err)
		}
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode generated CKLB: %v", err)
	}
	scrubGeneratedUUIDs(t, doc)

	canonical, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("canonicalize generated CKLB: %v", err)
	}
	sum := sha256.Sum256(canonical)
	got := hex.EncodeToString(sum[:])
	if got != rhel9V2R9GoldenDocumentSHA256 {
		t.Fatalf(
			"generated CKLB differs from the real STIG Viewer 3 RHEL 9 V2R9 export: sha256=%s, want %s (golden source sha256=%s)",
			got,
			rhel9V2R9GoldenDocumentSHA256,
			rhel9V2R9GoldenCKLBSourceSHA256,
		)
	}
}

func scrubGeneratedUUIDs(t *testing.T, doc map[string]any) {
	t.Helper()
	doc["id"] = ""

	stigs, ok := doc["stigs"].([]any)
	if !ok || len(stigs) != 1 {
		t.Fatalf("generated CKLB stigs = %#v", doc["stigs"])
	}
	stig, ok := stigs[0].(map[string]any)
	if !ok {
		t.Fatalf("generated CKLB STIG has unexpected type %T", stigs[0])
	}
	stig["uuid"] = ""

	rules, ok := stig["rules"].([]any)
	if !ok {
		t.Fatalf("generated CKLB rules have unexpected type %T", stig["rules"])
	}
	for i, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("generated CKLB rule %d has unexpected type %T", i, raw)
		}
		rule["uuid"] = ""
		rule["stig_uuid"] = ""
	}
}
