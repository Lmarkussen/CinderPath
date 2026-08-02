package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

var ErrAmbiguous = errors.New("artifact resolution is ambiguous")

type Record struct {
	ID, RunID, TargetFingerprint, Workflow, Stage, Type, Path, Fingerprint string
	CreatedAt                                                              time.Time
	Sensitive, Reviewed, Superseded                                        bool
}

type Registry struct {
	SchemaVersion int      `json:"schema_version"`
	Records       []Record `json:"records"`
}

func New() *Registry { return &Registry{SchemaVersion: 1, Records: []Record{}} }

func (r *Registry) Register(x Record) error {
	if x.ID == "" || x.RunID == "" || x.Workflow == "" || x.Stage == "" || x.Type == "" || x.Path == "" || x.Fingerprint == "" || x.CreatedAt.IsZero() {
		return errors.New("incomplete artifact record")
	}
	for _, existing := range r.Records {
		if existing.ID == x.ID {
			return errors.New("duplicate artifact ID")
		}
	}
	r.Records = append(r.Records, x)
	sortRecords(r.Records)
	return nil
}

func (r *Registry) ResolveLatest(runID, typ string) (Record, error) {
	var matches []Record
	for _, x := range r.Records {
		if x.RunID == runID && x.Type == typ && !x.Superseded {
			matches = append(matches, x)
		}
	}
	if len(matches) == 0 {
		return Record{}, os.ErrNotExist
	}
	sortRecords(matches)
	newest := matches[len(matches)-1]
	if len(matches) > 1 {
		other := matches[len(matches)-2]
		if other.CreatedAt.Equal(newest.CreatedAt) && other.ID != newest.ID {
			return Record{}, ErrAmbiguous
		}
	}
	return newest, nil
}

func (r *Registry) MarkReviewed(id string) error {
	return r.update(id, func(x *Record) { x.Reviewed = true })
}
func (r *Registry) MarkSensitive(id string) error {
	return r.update(id, func(x *Record) { x.Sensitive = true })
}
func (r *Registry) MarkSuperseded(id string) error {
	return r.update(id, func(x *Record) { x.Superseded = true })
}
func (r *Registry) update(id string, f func(*Record)) error {
	for i := range r.Records {
		if r.Records[i].ID == id {
			f(&r.Records[i])
			return nil
		}
	}
	return os.ErrNotExist
}

func VerifyFingerprint(path, expected string) error {
	actual, e := FileFingerprint(path)
	if e != nil {
		return e
	}
	if actual != expected {
		return fmt.Errorf("artifact fingerprint mismatch")
	}
	return nil
}
func FileFingerprint(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (r Registry) Save(path string) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func Load(path string) (Registry, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Registry{}, e
	}
	var r Registry
	if e = json.Unmarshal(b, &r); e != nil {
		return Registry{}, e
	}
	if r.SchemaVersion != 1 {
		return Registry{}, errors.New("unsupported artifact registry schema")
	}
	sortRecords(r.Records)
	return r, nil
}
func sortRecords(xs []Record) {
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].CreatedAt.Equal(xs[j].CreatedAt) {
			return xs[i].ID < xs[j].ID
		}
		return xs[i].CreatedAt.Before(xs[j].CreatedAt)
	})
}
