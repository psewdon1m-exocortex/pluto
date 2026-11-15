//go:build linux

package pluto

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Exercise the real public CLI, default TLS verification, actual partial SQLite
// initialization and the original plan digest. The server is a local fixture.
func TestPreparedAdoptionResumesInterruptedInitialPolicyThroughNativeCLI(t *testing.T) {
	for _, variant := range []string{"resume", "wrong-digest", "changed-input", "changed-profile", "wrong-stored-binding", "unknown-stored-codec", "pending-original", "activated-config", "source-owner", "remote-cut", "invalid-cap-binding", "invalid-cap-receipt", "invalid-cap-codec", "after-policy"} {
		t.Run(variant, func(t *testing.T) {
			var fail atomic.Bool
			fail.Store(true)
			var capabilityCalls atomic.Int64
			var f *cDaemonFixture
			f = cNativeWithHandler(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.HasSuffix(r.URL.Path, "/capabilities") {
						capabilityCalls.Add(1)
						w.Header().Set("Content-Type", "application/json")
						if fail.Load() && variant != "after-policy" && !strings.HasPrefix(variant, "invalid-cap-") {
							w.WriteHeader(http.StatusServiceUnavailable)
							return
						}
						caps := map[string]any{"schema": "saturn.sync-capabilities.v1", "binding": f.server.binding, "device_id": cUUID(51), "backend_identity": "backend-c", "qualification_receipt_sha256": cHash([]byte("qualification")), "features": []string{"snapshot-v1", "changes-v1", "folder-v2", "catalog-upload-v2"}, "extensions": map[string]any{"revisions": map[string]int{"K1": 2, "K2": 2, "K3": 2, "K4": 1}, "limits": map[string]int{"metadata_items": 500, "metadata_bytes": 4194304, "long_poll_ms": 25000, "gzip_threshold_bytes": 16384, "stream_chunk_bytes": 4194304, "stream_maximum_chunks": 256}, "namespace": map[string]string{"codec": "portable_v1", "policyHash": cHash([]byte("fixture-portable-policy"))}, "minimum_writer": "saturn.namespace-mutation.v1", "backend_policy": "managed-exclusive"}}
						if fail.Load() {
							switch variant {
							case "invalid-cap-binding":
								binding := map[string]any{}
								for k, v := range f.server.binding {
									binding[k] = v
								}
								binding["root_id"] = cUUID(999)
								caps["binding"] = binding
							case "invalid-cap-receipt":
								caps["qualification_receipt_sha256"] = cHash([]byte("wrong receipt"))
							case "invalid-cap-codec":
								caps["extensions"].(map[string]any)["namespace"].(map[string]string)["codec"] = "legacy"
							}
						}
						json.NewEncoder(w).Encode(caps)
						return
					}
					if variant == "after-policy" && fail.Load() && strings.HasSuffix(r.URL.Path, "/snapshots/start") {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					next.ServeHTTP(w, r)
				})
			})
			candidate := f.cfg.Indexed.Profile
			candidate.Remote.NameCodec = "portable_v1"
			candidate.Remote.Token = f.cfg.AccessToken
			f.cfg.Enabled, f.cfg.Indexed = false, nil
			if err := SaveJSON(f.config, f.cfg); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.state, "indexed-activation.json")); err != nil {
				t.Fatal(err)
			}
			profile := filepath.Join(f.base, "prepared-profile.json")
			if err := SaveJSON(profile, candidate); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(f.source, "retained.bin")
			if err := os.WriteFile(source, []byte("retain exact original source"), 0600); err != nil {
				t.Fatal(err)
			}
			hashFile := func(file string) string {
				b, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256(b)
				return hex.EncodeToString(h[:])
			}
			profileHash, sourceHash, configHash := hashFile(profile), hashFile(source), hashFile(f.config)
			raw, err := f.command("migrate-plan", "--profile", profile)
			if err != nil {
				t.Fatal(string(raw), err)
			}
			var plan AdoptionPlan
			if err = json.Unmarshal(raw, &plan); err != nil || !plan.Compatible {
				t.Fatal("initial plan", err)
			}
			raw, err = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest)
			if err == nil {
				t.Fatal("injected capability failure accepted")
			}
			t.Logf("retained initial CLI refusal: %s", raw)
			if capabilityCalls.Load() == 0 {
				t.Fatal("initial failure did not reach injected capability boundary")
			}
			var progress adoptionProgress
			b, err := os.ReadFile(filepath.Join(f.state, "indexed-adoption.json"))
			if err != nil || json.Unmarshal(b, &progress) != nil || progress.Phase != "PREPARED" || progress.PlanDigest != plan.Digest {
				t.Fatal("original PREPARED journal not retained", err)
			}
			if hashFile(profile) != profileHash || hashFile(source) != sourceHash || hashFile(f.config) != configHash {
				t.Fatal("failed first adoption changed input")
			}
			backups := map[string]string{}
			err = filepath.WalkDir(filepath.Join(f.state, "indexed", "sync-state-backups"), func(path string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if d.Type().IsRegular() {
					backups[path] = hashFile(path)
				}
				return nil
			})
			if err != nil {
				t.Fatal("migration backup inventory", err)
			}
			if len(backups) == 0 {
				t.Fatal("partial migration backups missing")
			}
			db, err := sql.Open("sqlite", filepath.Join(f.state, "indexed", "sync-state.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			var codec string
			expectedInitialCodec := "legacy"
			if variant == "after-policy" {
				expectedInitialCodec = "portable_v1"
			}
			if err = db.QueryRow("SELECT name_codec FROM roots").Scan(&codec); err != nil || codec != expectedInitialCodec {
				t.Fatal("not a genuine partial initialization", err)
			}
			if variant != "after-policy" {
				var remoteCount, policyTables int
				if err = db.QueryRow("SELECT COUNT(*) FROM remote_candidate_roots").Scan(&remoteCount); err != nil || remoteCount != 0 {
					t.Fatal("failed qualification created remote cut", err)
				}
				if err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='profile_policy'").Scan(&policyTables); err != nil || policyTables != 0 {
					t.Fatal("failed qualification installed policy", err)
				}
			}
			digest := plan.Digest
			switch variant {
			case "wrong-digest":
				digest = strings.Repeat("0", 64)
			case "changed-input":
				f.cfg.IntervalSeconds++
				err = SaveJSON(f.config, f.cfg)
			case "changed-profile":
				candidate.MappingID += "-different"
				err = SaveJSON(profile, candidate)
			case "wrong-stored-binding":
				_, err = db.Exec("UPDATE roots SET mapping_id='other'")
			case "unknown-stored-codec":
				_, err = db.Exec("UPDATE roots SET name_codec='unknown'")
			case "pending-original":
				_, err = db.Exec("INSERT INTO local_entries VALUES('root','retained',NULL,'name',1,'{}'); INSERT INTO operations(operation_id,root_id,entry_id,local_generation,kind,intent_json,intent_fingerprint,stage) VALUES('retained-original','root','retained',1,'PUT','{\"OperationID\":\"retained-original\"}','fingerprint','SUBMITTED')")
			case "activated-config":
				f.cfg.Indexed = &IndexedConfig{Activated: true, Profile: candidate, Policy: SourcePolicy{Revision: 1, Codec: "portable_v1", Excludes: []string{}}}
				err = SaveJSON(f.config, f.cfg)
			case "source-owner":
				_, err = db.Exec("UPDATE source_sets SET owner_id='active-owner',owner_sequence=1")
			case "remote-cut":
				_, err = db.Exec("INSERT INTO remote_entries VALUES('root',1,'remote',0,'{}')")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			fail.Store(false)
			callsBefore := capabilityCalls.Load()
			raw, err = f.command("adopt", "--profile", profile, "--plan-digest", digest)
			if variant != "resume" && variant != "after-policy" && !strings.HasPrefix(variant, "invalid-cap-") {
				if err == nil {
					t.Fatal("unsafe continuation accepted", variant)
				}
				if capabilityCalls.Load() != callsBefore {
					t.Fatal("rejected continuation contacted remote")
				}
			} else {
				if err != nil {
					t.Fatal(string(raw), err)
				}
				current, e := LoadConfig(f.config)
				if e != nil || current.Enabled || current.Indexed == nil || !current.Indexed.Activated || current.Indexed.Profile.LocalRootID != candidate.LocalRootID || current.Indexed.Profile.MappingID != candidate.MappingID || current.Indexed.Profile.SourceSetID != candidate.SourceSetID || current.Indexed.Profile.Sources[0].ID != candidate.Sources[0].ID {
					t.Fatal("activation identity/pause changed", e)
				}
				strict, e := inspectAdoption(t.Context(), f.state, current, candidate)
				if e != nil || !strict.Compatible || strict.Existing == nil || strict.Existing.Root.NameCodec != "portable_v1" || strict.Existing.Pending != 0 {
					t.Fatal("supported policy/strict compatibility not established", e)
				}
				if _, e = f.command("adopt", "--profile", profile, "--plan-digest", plan.Digest); e != nil {
					t.Fatal("idempotent completion", e)
				}
			}
			if hashFile(source) != sourceHash {
				t.Fatal("source bytes changed")
			}
			for path, hash := range backups {
				if hashFile(path) != hash {
					t.Fatal("retained backup changed")
				}
			}
		})
	}
}
