package pluto

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"pluto/internal/pluto/syncstate"
)

func TestEnduranceAdmissionRecoversUnsubmittedCapture(t *testing.T) {
	for _, mode := range []string{"partial", "readonly-complete", "foreign-inode", "linked"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			store, admission, _, source := admissionFixture(t)
			r, err := admission.Registry().Reserve(ctx, 33)
			if err != nil {
				t.Fatal(err)
			}
			f, err := r.Create(ctx)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("partial capture")
			if mode == "readonly-complete" {
				data = make([]byte, 33)
			}
			if _, err = f.Write(data); err != nil {
				t.Fatal(err)
			}
			if mode == "readonly-complete" {
				if err = f.Chmod(0400); err != nil {
					t.Fatal(err)
				}
			}
			if err = f.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			if err = r.Relinquish(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(admission.Registry().Directory(), r.ID()+".snapshot")
			if mode == "foreign-inode" {
				if err = os.Rename(name, name+".original"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "linked" {
				if err = os.Link(name, filepath.Join(t.TempDir(), "alias")); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(name)
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			if err = admission.Detach(); err != nil {
				t.Fatal(err)
			}
			reopened, err := syncstate.Open(ctx, filepath.Dir(admission.Registry().Directory()))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, err = reopened.EnableSources(ctx, syncstate.DefaultSourceLimits()); err != nil {
				t.Fatal(err)
			}
			next, report, err := BootstrapArtifactAdmission(ctx, reopened, syncstate.DefaultArtifactLimits())
			if mode == "foreign-inode" || mode == "linked" {
				if err == nil {
					t.Fatal("ambiguous capture admitted")
				}
				after, statErr := os.Lstat(name)
				if statErr != nil || !os.SameFile(before, after) {
					t.Fatal("foreign evidence changed", statErr)
				}
				return
			}
			if err != nil || !report.Admitted || report.ReservedBytes != 0 {
				t.Fatalf("unsubmitted capture blocks startup: %+v %v", report, err)
			}
			record, err := next.Registry().Record(ctx, r.ID())
			if err != nil || record.Phase != syncstate.ArtifactGone {
				t.Fatal(record, err)
			}
			if _, err = os.Lstat(name); !os.IsNotExist(err) {
				t.Fatal("abandoned temporary capture remains", err)
			}
			bytes, err := os.ReadFile(filepath.Join(source.SourceRootPath, "file"))
			if err != nil || string(bytes) != "exact bytes" {
				t.Fatal("source changed", err)
			}
			if err = reopened.Close(); err != nil {
				t.Fatal(err)
			}
			if err = next.Detach(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
