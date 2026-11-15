package syncstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"pluto/internal/syncproto"
	"time"
)

type folderFlight struct {
	op   Operation
	done chan struct{}
	raw  []byte
	err  error
}

// Singleflight by durable original. Independent parents coalesce for 5 ms;
// children are admitted in subsequent topology rounds after the imported ACK.
func (s *IsolatedHTTPSession) sendFolder(ctx context.Context, op Operation) ([]byte, error) {
	if op.FolderHTTP == nil || op.RootID != s.root || op.IntentFingerprint != fingerprint(op.Intent) || op.FolderHTTP.Identity.Origin != s.origin || op.FolderHTTP.Identity.InputBinding != s.binding {
		return nil, ErrIdentityConflict
	}
	if err := s.r.store.RetryReady(ctx, op.OperationID); err != nil {
		return nil, err
	}
	s.folderMu.Lock()
	if s.folderFlights == nil {
		s.folderFlights = map[string]*folderFlight{}
	}
	f := s.folderFlights[op.OperationID]
	if f == nil {
		if len(s.folderFlights) >= 500 {
			s.folderMu.Unlock()
			return nil, ErrSourceQuota
		}
		f = &folderFlight{op: op, done: make(chan struct{})}
		s.folderFlights[op.OperationID] = f
		s.folderQueue = append(s.folderQueue, f)
		if !s.folderSending {
			s.folderSending = true
			go s.flushFolders(ctx)
		}
	}
	s.folderMu.Unlock()
	<-f.done // Join transport before the session/database can close on pause.
	return f.raw, f.err
}
func (s *IsolatedHTTPSession) flushFolders(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Millisecond):
	}
	s.folderMu.Lock()
	page := s.folderQueue
	s.folderQueue = nil
	s.folderSending = false
	s.folderMu.Unlock()
	outcomes := make(map[string][]byte, len(page))
	failures := make(map[string]error, len(page))
	individual := !s.features["folder-batch-v1"]
	if !individual {
		items := make([]map[string]any, 0, len(page))
		helpers := map[string]Operation{}
		parentRefs := map[string]string{}
		queued := map[string]bool{}
		for _, f := range page {
			queued[f.op.OperationID] = true
		}
		// Siblings may reference a replay of their original confirmed parent.
		// This uses local refs without inventing a future node ID or rewriting
		// any child's immutable input. New-depth parents still use bounded rounds.
		if len(page) > 1 {
			for _, f := range page {
				input := f.op.FolderHTTP.Input
				if len(input.ParentTopology) < 2 {
					continue
				}
				parent := input.ParentID
				if _, seen := parentRefs[parent]; seen {
					continue
				}
				parentRefs[parent] = ""
				var id string
				e := s.r.store.db.QueryRowContext(ctx, "SELECT operation_id FROM operations WHERE root_id=? AND kind='ENSURE_DIRECTORY' AND stage='CLIENT_ACKED' AND json_extract(receipt_json,'$.Description.NodeID')=? ORDER BY operation_id LIMIT 1", s.root, parent).Scan(&id)
				if e != nil || queued[id] {
					continue
				}
				op, e := s.r.store.Operation(ctx, id)
				if e != nil || op.FolderHTTP == nil || op.IntentFingerprint != fingerprint(op.Intent) || op.FolderHTTP.Identity.InputBinding != s.binding || op.FolderHTTP.Input.Name != input.ParentTopology[0].Name || !bytes.Equal(mustJSON(op.FolderHTTP.Input.ParentTopology), mustJSON(input.ParentTopology[1:])) {
					continue
				}
				if len(items)+len(page) >= 500 {
					break
				}
				helpers[id] = op
				parentRefs[parent] = id
				items = append(items, map[string]any{"ref": id, "input": op.FolderHTTP.Input})
			}
		}
		for _, f := range page {
			item := map[string]any{"ref": f.op.OperationID, "input": f.op.FolderHTTP.Input}
			if parent := parentRefs[f.op.FolderHTTP.Input.ParentID]; parent != "" {
				item["parentRef"] = parent
			}
			items = append(items, item)
		}
		raw, err := s.post(ctx, "directories/batch", map[string]any{"binding": bindingHTTP(s.binding), "items": items})
		if HTTPStatus(err) == 404 || HTTPStatus(err) == 413 || HTTPStatus(err) == 501 || errors.Is(err, ErrSourceQuota) {
			individual = true
		} else if err != nil {
			for _, f := range page {
				failures[f.op.OperationID] = err
			}
		} else {
			parsed, e := syncproto.Parse(raw)
			m, ok := parsed.(map[string]any)
			if e != nil || !ok || m["schema"] != "saturn.folder-batch-result.v1" {
				err = ErrInvalidReceipt
			} else {
				rows, ok := m["items"].([]any)
				if !ok || len(rows) != len(items) {
					err = ErrInvalidReceipt
				} else {
					seen := map[string]bool{}
					known := map[string]bool{}
					for id := range helpers {
						known[id] = true
					}
					for _, f := range page {
						known[f.op.OperationID] = true
					}
					for _, row := range rows {
						v, ok := row.(map[string]any)
						if !ok {
							err = ErrInvalidReceipt
							break
						}
						ref, ok := v["ref"].(string)
						if !ok || !known[ref] || seen[ref] {
							err = ErrInvalidReceipt
							break
						}
						seen[ref] = true
						if outcome, ok := v["outcome"]; ok {
							outcomes[ref] = mustJSON(outcome)
							if helper, exists := helpers[ref]; exists {
								if _, e = readFolderHTTPReceipt(outcomes[ref], helper); e != nil {
									err = e
									break
								}
							}
						} else if code, ok := v["code"].(string); ok {
							failures[ref] = &guardedHTTPFailure{status: 409, code: code, path: "directories/batch", binding: s.binding, transportPin: s.transportPin}
						} else {
							err = ErrInvalidReceipt
							break
						}
					}
				}
			}
			if err != nil {
				for _, f := range page {
					failures[f.op.OperationID] = err
				}
			}
		}
	}
	if individual {
		for _, f := range page {
			outcomes[f.op.OperationID], failures[f.op.OperationID] = s.post(ctx, "directories/ensure-v2", map[string]any{"binding": bindingHTTP(s.binding), "input": f.op.FolderHTTP.Input})
		}
	}
	s.folderMu.Lock()
	defer s.folderMu.Unlock()
	for _, f := range page {
		f.raw = outcomes[f.op.OperationID]
		f.err = failures[f.op.OperationID]
		delete(s.folderFlights, f.op.OperationID)
		close(f.done)
	}
}

func parentCacheKey(w RemoteWitness, codec string) string {
	return fingerprint(struct {
		Binding           RemoteBinding
		Generation, Trust int64
		Codec             string
	}{w.Binding, w.Generation, w.TrustGeneration, codec})
}

// A cache never grants authority: positives reread the node from current R;
// negatives are invalidated atomically by every feed mutation of the name.
func cachedParent(ctx context.Context, tx *sql.Tx, w RemoteWitness, codec, parent, name string) (*RemoteEntry, bool, error) {
	cacheName := name
	if codec == "portable_v1" {
		var err error
		cacheName, err = syncproto.NameKey(name, codec)
		if err != nil {
			return nil, false, err
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, false, err
	}
	if version != daemonSchemaVersion {
		return nil, false, nil
	}
	var node, metadata string
	var expires int64
	err := tx.QueryRowContext(ctx, "SELECT node_id,metadata_version,expires_ms FROM parent_cache WHERE root_id=? AND binding_key=? AND destination=?", w.RootID, parentCacheKey(w, codec), parent+"/"+cacheName).Scan(&node, &metadata, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if expires < time.Now().UnixMilli() {
		return nil, false, nil
	}
	if node == "" {
		return nil, true, nil
	}
	entry, err := readJSON[RemoteEntry](ctx, tx, "SELECT descriptor_json FROM remote_entries WHERE root_id=? AND generation=? AND node_id=?", w.RootID, w.Generation, node)
	if err != nil || entry.ParentID != parent || entry.Name != name || entry.Version != metadata || entry.Kind != "folder" || entry.Presence != "PRESENT" || !currentRemoteBinding(entry, w) {
		return nil, false, nil
	}
	return &entry, true, nil
}
func rememberParent(ctx context.Context, tx *sql.Tx, w RemoteWitness, codec, parent, name string, entry *RemoteEntry) error {
	cacheName := name
	if codec == "portable_v1" {
		var err error
		cacheName, err = syncproto.NameKey(name, codec)
		if err != nil {
			return err
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != daemonSchemaVersion || entry != nil && entry.Kind != "folder" {
		return nil
	}
	node, metadata := "", ""
	ttl := 5 * time.Second
	if entry != nil {
		node, metadata = entry.NodeID, entry.Version
		ttl = time.Minute
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM parent_cache WHERE root_id=? AND (expires_ms<? OR binding_key<>?)", w.RootID, time.Now().UnixMilli(), parentCacheKey(w, codec)); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM parent_cache WHERE root_id=?", w.RootID).Scan(&count); err != nil {
		return err
	}
	if count >= 4096 {
		return nil
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO parent_cache(root_id,binding_key,destination,node_id,metadata_version,expires_ms) VALUES(?,?,?,?,?,?) ON CONFLICT(root_id,binding_key,destination) DO UPDATE SET node_id=excluded.node_id,metadata_version=excluded.metadata_version,expires_ms=excluded.expires_ms", w.RootID, parentCacheKey(w, codec), parent+"/"+cacheName, node, metadata, time.Now().Add(ttl).UnixMilli())
	return err
}
