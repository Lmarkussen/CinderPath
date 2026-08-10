package recon4

import "testing"

func TestNormalizeRows(t *testing.T) {
	rows, err := normalizeRows([]map[string]any{{"Device": "CLIENT", "Caption": "Windows"}})
	if err != nil || len(rows) != 1 || rows[0]["Device"] != "CLIENT" {
		t.Fatalf("unexpected normalization: %#v %v", rows, err)
	}
}

func TestNormalizeRowsBounds(t *testing.T) {
	tooMany := make([]map[string]any, maxRows+1)
	if _, err := normalizeRows(tooMany); err == nil {
		t.Fatal("expected row bound")
	}
	long := map[string]any{"Device": string(make([]byte, maxField+1))}
	if _, err := normalizeRows([]map[string]any{long}); err == nil {
		t.Fatal("expected field bound")
	}
}

func TestFixedQuery(t *testing.T) {
	if FixedQuery != "OperatingSystem" {
		t.Fatalf("unexpected fixed query %q", FixedQuery)
	}
}
