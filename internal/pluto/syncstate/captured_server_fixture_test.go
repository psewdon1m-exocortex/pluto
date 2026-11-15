package syncstate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"pluto/internal/syncproto"
	"testing"
	"time"
)

func boundedServerFixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	f, e := os.Open(filepath.Join(dir, name))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, syncproto.MaxBytes+1))
	if e != nil || len(raw) > syncproto.MaxBytes {
		t.Fatal("fixture raw bound", e)
	}
	return raw
}
func TestCapturedServerActualSQLBackedSnapshotFeedExact64(t *testing.T) {
	base := os.Getenv("PLUTO_R1C_SERVER_FIXTURES")
	if base == "" {
		t.Skip("dedicated root-frozen actual S2 fixture gate requires PLUTO_R1C_SERVER_FIXTURES")
	}
	var fixtures struct {
		Schema int `json:"schema"`
		Cases  []struct {
			Directory string `json:"directory"`
			Seed      string `json:"seed"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(boundedServerFixture(t, base, "fixture-cases.json")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixtures); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("trailing fixture manifest data", err)
	}
	if fixtures.Schema != 1 || len(fixtures.Cases) != 2 {
		t.Fatal("two original SQL-backed counter cases required")
	}
	expectedCuts := map[string]int64{"0": 1, "9007199254740993": 9007199254740994}
	seen := map[string]bool{}
	for _, fixture := range fixtures.Cases {
		id := fixture.Directory
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id {
			t.Fatal("invalid original fixture directory", id)
		}
		expectedCut, ok := expectedCuts[fixture.Seed]
		if !ok || seen[fixture.Seed] {
			t.Fatal("missing or duplicated exact counter seed", fixture.Seed)
		}
		seen[fixture.Seed] = true
		t.Run(id, func(t *testing.T) {
			dir := filepath.Join(base, id)
			ready := boundedServerFixture(t, dir, "ready.json")
			snapshot, e := syncproto.ReadSnapshot(ready)
			if e != nil {
				t.Fatal(e)
			}
			s, w, _ := sourceFixture(t, t.TempDir())
			b := testBinding
			b.SourceIdentity = w.SetID
			b.ServerIdentity = snapshot.ServerIdentity
			b.RemoteRootID = snapshot.RootID
			if e = s.store.BindRoot(testContext, b); e != nil {
				t.Fatal(e)
			}
			if e = s.AttachSourceSet(testContext, w.SetID, w.Revision, "root"); e != nil {
				t.Fatal(e)
			}
			a, e := s.store.EnableArtifacts(testContext, DefaultArtifactLimits())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = a.Reconcile(testContext, artifactTestReader); e != nil {
				t.Fatal(e)
			}
			r, e := s.store.EnableRemoteImport(testContext)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now()
			p, e := r.PrepareSnapshot(testContext, "root", 1, ready, now)
			if e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"entries-page-1.json", "entries-page-2.json", "entries-page-3.json", "entries-page-4.json"} {
				p, e = r.ImportSnapshotPage(testContext, "root", p.Cursor, boundedServerFixture(t, dir, name), now)
				if e != nil {
					t.Fatal(name, e)
				}
			}
			c, e := r.PublishSnapshot(testContext, "root", p, now)
			if e != nil {
				t.Fatal(e)
			}
			original := c.Position
			for _, name := range []string{"empty-feed.json", "replayed-feed.json", "fresh-feed.json", "feed-500.json", "feed-tail.json"} {
				before := c
				c, e = r.ImportFeed(testContext, c.RemoteWitness, boundedServerFixture(t, dir, name))
				if e != nil {
					t.Fatal(name, e)
				}
				again, e := r.ImportFeed(testContext, before.RemoteWitness, boundedServerFixture(t, dir, name))
				if e != nil || fingerprint(again) != fingerprint(c) {
					t.Fatal("exact replay", name, e)
				}
			}
			if c.Position != original+505 {
				t.Fatal("64-bit sequence rounded or incomplete", original, c.Position)
			}
			if original != expectedCut {
				t.Fatal("seed rounded", original)
			}
			root, e := s.store.Root(testContext, "root")
			if e != nil || root.EngineReady {
				t.Fatal("shape activated engine", root, e)
			}
			cursor, e := s.store.Cursor(testContext, "root", "remote")
			if e != nil || cursor.Valid {
				t.Fatal("raw signed-looking cursor granted authority", cursor, e)
			}
			t.Logf("actual root S2 raw imported: cut=%d final=%d, seven-field binding preserved, authority closed", original, c.Position)
		})
	}
}
