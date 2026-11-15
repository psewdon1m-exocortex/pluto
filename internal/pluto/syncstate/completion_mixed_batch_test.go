package syncstate

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Use the production wire decoder, native aggregate and reopened SQLite store.
// The server commits a heterogeneous prepare result, then loses its response.
func TestCompletionMixedSixOriginalsAfterLostResponse(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		name := "subset-enabled"
		if disabled {
			name = "new-admission-disabled"
		}
		t.Run(name, func(t *testing.T) {
			var rejectedID string
			d, f, p, _ := dispatchFixtureWithHandler(t, 6, func(f *dispatchHTTPFixture) http.Handler {
				lost := false
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					rr := httptest.NewRecorder()
					f.ServeHTTP(rr, req)
					if !lost && strings.HasSuffix(req.URL.Path, "/small-batches/prepare") {
						lost = true
						f.base.lose(w)
						return
					}
					var body map[string]any
					if json.Unmarshal(rr.Body.Bytes(), &body) == nil {
						fix := func(status map[string]any) {
							if result, ok := status["result"].(map[string]any); ok && result["status"] == "NOT_PUBLISHED" {
								status["session"].(map[string]any)["phase"] = "not_published"
							}
						}
						fix(body)
						if items, ok := body["items"].([]any); ok {
							for _, v := range items {
								item := v.(map[string]any)
								if item["operation_id"] == "pluto-sync-"+rejectedID {
									item["state"] = "NOT_PUBLISHED"
									fix(item["status"].(map[string]any))
								}
							}
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(rr.Code)
						json.NewEncoder(w).Encode(body)
						return
					}
					w.WriteHeader(rr.Code)
					w.Write(rr.Body.Bytes())
				})

			})
			rejected := p.entries[5].original
			rejectedID = rejected.OperationID
			initialNodes := len(f.base.nodes)
			f.base.mu.Lock()
			for n := 0; n < 2; n++ {
				if err := f.publish(p.entries[n].original, []byte("one")); err != nil {
					t.Fatal(err)
				}
			}
			partial := p.entries[4].original
			input, err := originalCatalogInput(partial)
			if err != nil {
				t.Fatal(err)
			}
			partialID := remoteVersion(7000)
			f.base.uploads[partial.OperationID] = &httpFixtureUpload{op: partial, input: input, serverID: partialID, bytes: []byte("o")}
			ri, err := originalCatalogInput(rejected)
			if err != nil {
				t.Fatal(err)
			}
			rejectedUploadID := remoteVersion(7001)
			f.base.uploads[rejected.OperationID] = &httpFixtureUpload{op: rejected, input: ri, serverID: rejectedUploadID, result: map[string]any{
				"schema": "saturn.catalog-upload-result.v2", "status": "NOT_PUBLISHED", "uploadId": rejectedUploadID,
				"operationId": rejectedUploadID, "rootId": f.base.binding.RootID, "intentHash": ri.hash, "reason": "cancelled_before_publication",
			}}
			f.base.mu.Unlock()
			open := func(r *RemoteImport) *IsolatedHTTPSession {
				old := d.session
				s, e := NewIsolatedHTTPSession(testContext, r, "root", IsolatedHTTPConfig{Domain: IsolatedHTTPContract, Origin: old.origin, AllowedAddresses: []string{"127.0.0.1"}, Binding: bindingHTTP(old.binding), DeviceID: old.identity.DeviceID, BackendIdentity: old.identity.BackendIdentity, QualificationReceiptSHA256: old.identity.ContractReceiptSHA256, Token: "fixture-token"})
				if e != nil {
					t.Fatal(e)
				}
				s.SetRecoveryReader(artifactTestReader)
				t.Cleanup(s.Close)
				f.session = s
				return s
			}
			d.session.Close()
			d.session = open(d.session.r)
			if err = d.dispatch(testContext, p); err == nil {
				t.Fatal("lost response accepted")
			}
			saved, err := d.native.state.read(testContext, p.id)
			if err != nil || saved.Phase != "ATTEMPTED" {
				t.Fatal(saved.Phase, err)
			}
			directory := filepath.Dir(d.session.r.store.filename)
			d.session.Close()
			if err = d.session.r.store.Close(); err != nil {
				t.Fatal(err)
			}
			r, native := reopenNativeSmallBatch(t, directory)
			f.base.r = r
			s := open(r)
			d, err = newSmallBatchDispatcher(native, s, artifactTestReader)
			if err != nil {
				t.Fatal(err)
			}
			if disabled {
				shared, e := newBudgetedSmallBatchArtifacts(testContext, native, &fixtureSmallBatchBudget{})
				if e != nil {
					t.Fatal(e)
				}
				engine := &smallBatchScanEngine{dispatcher: d, shared: shared, recovered: map[string]bool{}}
				if e = engine.resume(testContext, ""); e != nil {
					t.Fatal(e)
				}
				for n, entry := range p.entries {
					e = d.recoverOriginal(testContext, entry.original)
					if n == 5 {
						if !errors.Is(e, ErrArtifactRetained) {
							t.Fatal("rejected original", e)
						}
					} else if e != nil {
						t.Fatal(e)
					}
				}
			} else if err = d.dispatch(testContext, saved.Plan); !errors.Is(err, ErrArtifactRetained) {
				t.Fatal("expected retained rejected original", err)
			}
			for n, entry := range p.entries {
				op, e := r.store.Operation(testContext, entry.original.OperationID)
				if e != nil || op.IntentFingerprint != entry.original.IntentFingerprint || op.SealedFingerprint != entry.original.SealedFingerprint || op.LocalGeneration != entry.original.LocalGeneration {
					t.Fatal("original changed", n, e)
				}
				if n == 5 {
					if op.Stage == "CLIENT_ACKED" {
						t.Fatal("rejection became ACK")
					}
					if e = r.store.artifacts.WithRecoveryReader(testContext, op, artifactTestReader, func(reader io.Reader) error {
						b, e := io.ReadAll(reader)
						if string(b) != "one" {
							t.Error("rejected original lost")
						}
						return e
					}); e != nil {
						t.Fatal(e)
					}
				} else {
					state, e := r.store.Entry(testContext, op.RootID, op.EntryID)
					if op.Stage != "CLIENT_ACKED" || e != nil || state.Base == nil || state.Base.OperationID != op.OperationID || state.Dirty == nil {
						t.Fatal("historical ACK cleared current work", n, op.Stage, e)
					}
				}
				want := 0
				if !disabled && (n == 2 || n == 3) {
					want = 1
				}
				if f.sent[op.OperationID] != want {
					t.Fatal("wrong subset membership", n, f.sent)
				}
			}
			if f.base.uploads[partial.OperationID].serverID != partialID || string(f.base.uploads[partial.OperationID].bytes) != "one" {
				t.Fatal("partial identity/offset changed")
			}
			if len(f.base.nodes) != initialNodes+5 {
				t.Fatal("duplicate or missing publication", len(f.base.nodes))
			}
			if s.Metrics().DataBytes != 8 {
				t.Fatal("accepted or rejected bytes resent", s.Metrics())
			}
			wantData, wantAppend := 1, 1
			if disabled {
				wantData, wantAppend = 0, 3
			}
			if f.calls["data"] != wantData || f.base.requests["catalog-uploads/append"] != wantAppend {
				t.Fatal(f.calls, f.base.requests)
			}
		})
	}
}
