package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rec(id, run, typ string, at time.Time) Record {
	return Record{ID: id, RunID: run, TargetFingerprint: "target", Workflow: "assessment", Stage: "collect", Type: typ, Path: "artifact.json", Fingerprint: "abc", CreatedAt: at}
}
func TestRegisterResolveAndReview(t *testing.T) {
	r := New()
	now := time.Unix(1, 0).UTC()
	if e := r.Register(rec("a", "run", "client_inventory", now)); e != nil {
		t.Fatal(e)
	}
	if e := r.MarkSensitive("a"); e != nil {
		t.Fatal(e)
	}
	if e := r.MarkReviewed("a"); e != nil {
		t.Fatal(e)
	}
	x, e := r.ResolveLatest("run", "client_inventory")
	if e != nil || !x.Sensitive || !x.Reviewed {
		t.Fatalf("%+v %v", x, e)
	}
	if e = r.MarkSuperseded("a"); e != nil {
		t.Fatal(e)
	}
	if _, e = r.ResolveLatest("run", "client_inventory"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}
func TestAmbiguousLatestRejected(t *testing.T) {
	r := New()
	now := time.Unix(1, 0).UTC()
	_ = r.Register(rec("a", "run", "capture", now))
	_ = r.Register(rec("b", "run", "capture", now))
	if _, e := r.ResolveLatest("run", "capture"); !errors.Is(e, ErrAmbiguous) {
		t.Fatal(e)
	}
}
func TestPersistenceAndFingerprint(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "artifact")
	b := []byte("safe synthetic artifact")
	_ = os.WriteFile(p, b, 0600)
	sum := sha256.Sum256(b)
	if e := VerifyFingerprint(p, hex.EncodeToString(sum[:])); e != nil {
		t.Fatal(e)
	}
	r := New()
	_ = r.Register(rec("a", "run", "dossier", time.Unix(1, 0).UTC()))
	rp := filepath.Join(d, "registry.json")
	if e := r.Save(rp); e != nil {
		t.Fatal(e)
	}
	loaded, e := Load(rp)
	if e != nil || len(loaded.Records) != 1 {
		t.Fatalf("%v %+v", e, loaded)
	}
	st, _ := os.Stat(rp)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
}
