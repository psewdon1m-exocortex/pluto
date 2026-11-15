package pluto

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func nativeMetadataCount(t *testing.T, f *cDaemonFixture, query string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(f.state, "indexed/sync-state.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err = db.QueryRow(query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestMetadataFollowupNativeDisabledCapabilityKeepsNoopOriginals(t *testing.T) {
	f := cNative(t)
	if err := os.WriteFile(filepath.Join(f.source, "one.bin"), []byte("native no optional namespace capability"), 0600); err != nil {
		t.Fatal(err)
	}
	stop := f.start()
	defer stop(false)
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
	})
	if f.status().Observation.Engine.Features["namespace-mutations-v1"] {
		t.Fatal("fixture unexpectedly negotiated metadata")
	}
	before := nativeMetadataCount(t, f, "SELECT count(*) FROM operations")
	if nativeMetadataCount(t, f, "SELECT count(*) FROM source_dirty") != 0 {
		t.Fatal("disabled metadata capability queued followup")
	}
	for _, action := range []string{"pause", "resume"} {
		if out, err := f.command(action); err != nil {
			t.Fatal(action, string(out), err)
		}
	}
	cAwait(t, func() bool {
		s := f.status()
		return s.Observation.Engine != nil && s.Observation.Engine.Phase == "observing"
	})
	if after := nativeMetadataCount(t, f, "SELECT count(*) FROM operations"); after != before {
		t.Fatal("disabled feature created original", before, after)
	}
	if nativeMetadataCount(t, f, "SELECT count(*) FROM operations WHERE kind='METADATA_PATCH'") != 0 {
		t.Fatal("unnegotiated metadata mutation")
	}
}

func TestMetadataFollowupManualPausedCopyCancelsWithContinuousHints(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := cNativeWithHandler(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "catalog-uploads/complete") {
				once.Do(func() { close(entered) })
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	f.cfg.Enabled = false
	if err := SaveJSON(f.config, f.cfg); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(f.source, "mutable.bin")
	if err := os.WriteFile(filename, bytes.Repeat([]byte("a"), 49152), 0600); err != nil {
		t.Fatal(err)
	}
	stop := f.start()
	defer stop(false)
	body, _ := json.Marshal(Control{Action: "run"})
	response, err := LocalClient(f.socket).Post("http://localhost/control", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("manual copy did not reach publication")
	}
	mutatorStop, mutatorDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(mutatorDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		value := byte('b')
		for {
			select {
			case <-mutatorStop:
				return
			case <-ticker.C:
				_ = os.WriteFile(filename, bytes.Repeat([]byte{value}, 49152), 0600)
				value++
				if value > 'z' {
					value = 'b'
				}
			}
		}
	}()
	defer func() { close(mutatorStop); <-mutatorDone }()
	time.Sleep(150 * time.Millisecond)
	close(release)
	cAwait(t, func() bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		for _, u := range f.server.uploads {
			if u.Result != nil {
				return true
			}
		}
		return false
	})
	time.Sleep(150 * time.Millisecond)
	if !f.status().Running || f.status().Observation.Enabled {
		t.Fatal("disabled manual run did not retain pending hint completion", f.status())
	}
	if nativeMetadataCount(t, f, "SELECT count(*) FROM source_dirty") == 0 {
		t.Fatal("no continuous hint pressure was exercised")
	}
	started := time.Now()
	result := make(chan error, 1)
	f.processes.OwnGo(func() { _, err := f.command("pause"); result <- err })
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pause waited for mutable-source quiescence")
	}
	cAwait(t, func() bool { return !f.status().Running })
	if time.Since(started) > 5*time.Second || f.status().Observation.Enabled {
		t.Fatal("pause failed to cancel disabled manual copy")
	}
}
