//go:build linux && pluto_archival_reader

package syncstate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// SHA-256 of the original C-native-final/old-v6-reader from the binary manifest.
const historicalReaderSHA256 = "52a9c6533953dff9b1ef1195f3bc144dcf35d41264affaf3020b39cbcd191999"

func TestStage3C03ActualHistoricalWriterRefusesV8(t *testing.T) {
	reader := os.Getenv("STAGE3_C_OLD_READER")
	if !filepath.IsAbs(reader) {
		t.Fatal("set STAGE3_C_OLD_READER to the absolute path of the original archival reader")
	}
	digest, err := fileDigest(reader)
	if err != nil {
		t.Fatalf("read original archival reader: %v", err)
	}
	if digest != historicalReaderSHA256 {
		t.Fatalf("archival reader SHA-256 mismatch: got %s, want %s", digest, historicalReaderSHA256)
	}

	r, _, _, _ := stage3Daemon(t, 0)
	directory := filepath.Dir(r.store.filename)
	if err := r.store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.store.filename)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(reader, directory).CombinedOutput()
	if err != nil || !bytes.Contains(raw, []byte("sync state schema is unsupported")) {
		t.Fatal("historical writer", string(raw), err)
	}
	after, err := os.ReadFile(r.store.filename)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("historical writer changed database", err)
	}
	current, err := Open(testContext, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
}
