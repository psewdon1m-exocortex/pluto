//go:build linux

package pluto

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nativeBulkLocalBackup struct {
	directory, archiveSHA, requestID string
	before                           []admissionPhysicalEntry
	entries                          []admissionBackupEntry
	remote                           json.RawMessage
}
type nativeBulkCheckpointProof struct {
	Schema                        string `json:"schema"`
	Status                        string `json:"status"`
	RequestID                     string `json:"requestID"`
	GraphSHA256                   string `json:"graphSHA256"`
	PostgreSQLRestored            bool   `json:"postgreSQLRestored"`
	FullSQLRowsCompared           bool   `json:"fullSQLRowsCompared"`
	PhysicalSFTPRestored          bool   `json:"physicalSFTPRestored"`
	AllPhysicalBytesCompared      bool   `json:"allPhysicalBytesCompared"`
	ActualProductReadback         bool   `json:"actualProductReadback"`
	AuthorityConfigRestored       bool   `json:"authorityConfigRestored"`
	OriginalBackendStoppedReceipt bool   `json:"originalBackendStoppedReceipt"`
	OriginalBackendResumed        bool   `json:"originalBackendResumed"`
	CanaryBytes                   int64  `json:"canaryBytes"`
	NativeArchiveSHA256           string `json:"nativeArchiveSHA256"`
}

func nativeBulkPhysical(t *testing.T, f *cDaemonFixture) []admissionPhysicalEntry {
	t.Helper()
	var result []admissionPhysicalEntry
	for _, root := range []string{f.config, f.ca, f.state, f.source} {
		if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("exact owned original graph required")
			}
			row := admissionPhysicalEntry{Path: p, Kind: "directory", Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, Bytes: info.Size(), MTimeNS: info.ModTime().UnixNano(), CTimeNS: st.Ctim.Sec*1e9 + st.Ctim.Nsec}
			if !info.IsDir() {
				if !info.Mode().IsRegular() || st.Nlink != 1 {
					return fmt.Errorf("single-link original regular file required")
				}
				row.Kind = "file"
				row.SHA256, err = admissionFileDigest(p)
				if err != nil {
					return err
				}
			}
			result = append(result, row)
			if len(result) > 8192 {
				return fmt.Errorf("bounded native graph required")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return result
}
func nativeBulkPrivateRoot(t *testing.T, name string) {
	t.Helper()
	info, err := os.Lstat(name)
	if err != nil || !filepath.IsAbs(name) || filepath.Clean(name) != name || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("explicit private disk backup root required", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("backup root owner differs")
	}
}
func nativeBulkArchive(t *testing.T, f *cDaemonFixture) *nativeBulkLocalBackup {
	t.Helper()
	if t.Name() != "TestCompletionNativeBulkReadbackPauseRestartNoCopies" || f.processes == nil || f.processes.scope.Base != f.base || os.Getenv("COMPLETION_REUSE_BASE") != "" {
		t.Fatal("fresh exact Root-owned ordinary bulk fixture required")
	}
	base := os.Getenv("PLUTO_BULK_BACKUP_DIR")
	nativeBulkPrivateRoot(t, base)
	for _, root := range []string{f.config, f.ca, f.state, f.source} {
		relative, err := filepath.Rel(f.base, root)
		resolved, e := filepath.EvalSymlinks(root)
		if err != nil || e != nil || !filepath.IsLocal(relative) || relative == "." || resolved != root {
			t.Fatal("full original fixture root required", root, err, e)
		}
	}
	cfg, err := LoadConfig(f.config)
	if err != nil || len(cfg.Sources) != 1 || cfg.Sources[0] != f.source || cfg.Indexed == nil || len(cfg.Indexed.Profile.Sources) != 1 || cfg.Indexed.Profile.Sources[0].SelectedPath != f.source {
		t.Fatal("all selected original sources must be included", err)
	}
	// This barrier precedes the first native daemon start. Preserve the actual
	// absence of SQLite, rather than manufacturing an empty database as a backup.
	initialDB := filepath.Join(f.state, "indexed", "sync-state.sqlite")
	if _, err = os.Lstat(initialDB); !os.IsNotExist(err) {
		t.Fatal("fresh pre-start profile must have no SQLite writer", err)
	}
	if _, err = os.Lstat(f.socket); !os.IsNotExist(err) {
		t.Fatal("native child must not have started before checkpoint", err)
	}
	directory, err := os.MkdirTemp(base, "bulk-closed-")
	if err != nil {
		t.Fatal(err)
	}
	b := &nativeBulkLocalBackup{directory: directory, requestID: emptyReservationID(t), before: nativeBulkPhysical(t, f)}
	authority := filepath.Join(directory, "authority-source")
	if err = os.Mkdir(authority, 0700); err != nil {
		t.Fatal(err)
	}
	if f.http.TLS == nil || len(f.http.TLS.Certificates) != 1 {
		t.Fatal("actual native TLS authority required")
	}
	certificate := f.http.TLS.Certificates[0]
	var chain []byte
	for _, der := range certificate.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	private, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	for name, raw := range map[string][]byte{"chain.pem": chain, "key.pem": key} {
		file, err := os.OpenFile(filepath.Join(authority, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, e := file.Write(raw)
		syncErr, closeErr := file.Sync(), file.Close()
		if e != nil || syncErr != nil || closeErr != nil {
			t.Fatal(e, syncErr, closeErr)
		}
	}
	admissionDirectorySync(t, authority)
	roots := []struct{ label, path string }{{"config.json", f.config}, {"ca.pem", f.ca}, {"state", f.state}, {"source", f.source}, {"fixture-tls", authority}}
	originalFor := func(name string) string {
		parts := strings.SplitN(name, "/", 2)
		for _, root := range roots {
			if parts[0] == root.label {
				if len(parts) == 1 {
					return root.path
				}
				return filepath.Join(root.path, filepath.FromSlash(parts[1]))
			}
		}
		t.Fatal("unknown archive label")
		return ""
	}
	inventory := func() []admissionBackupEntry {
		var entries []admissionBackupEntry
		var total int64
		for _, root := range roots {
			if err := filepath.WalkDir(root.path, func(p string, d fs.DirEntry, e error) error {
				if e != nil {
					return e
				}
				info, e := d.Info()
				if e != nil {
					return e
				}
				relative, e := filepath.Rel(root.path, p)
				if e != nil {
					return e
				}
				name := root.label
				if relative != "." {
					name += "/" + filepath.ToSlash(relative)
				}
				row := admissionBackupEntry{Name: name, Directory: info.IsDir(), Mode: info.Mode().Perm()}
				if !info.IsDir() {
					if !info.Mode().IsRegular() {
						return fmt.Errorf("unsupported graph object")
					}
					row.Bytes = info.Size()
					total += row.Bytes
					if total > 64<<20 {
						return fmt.Errorf("native fixture exceeds64MiB")
					}
					row.SHA256, e = admissionFileDigest(p)
					if e != nil {
						return e
					}
				}
				entries = append(entries, row)
				if len(entries) > 8192 {
					return fmt.Errorf("native graph exceeds8192entries")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		return entries
	}
	b.entries = inventory()
	archive := filepath.Join(directory, "native-profile-source-authority.tar")
	output, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(output)
	for _, entry := range b.entries {
		kind := byte(tar.TypeReg)
		if entry.Directory {
			kind = tar.TypeDir
		}
		if err = tw.WriteHeader(&tar.Header{Name: entry.Name, Mode: int64(entry.Mode.Perm()), Size: entry.Bytes, Typeflag: kind}); err != nil {
			t.Fatal(err)
		}
		if !entry.Directory {
			file, err := os.Open(originalFor(entry.Name))
			if err != nil {
				t.Fatal(err)
			}
			n, e := io.Copy(tw, file)
			closeErr := file.Close()
			if n != entry.Bytes || e != nil || closeErr != nil {
				t.Fatal("actual native archive", e, closeErr)
			}
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = output.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = output.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.entries, inventory()) || !reflect.DeepEqual(b.before, nativeBulkPhysical(t, f)) {
		t.Fatal("original graph changed during archive")
	}
	b.archiveSHA, err = admissionFileDigest(archive)
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(directory, "restored")
	if err = os.Mkdir(restored, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	var directories []string
	for {
		header, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		relative := filepath.FromSlash(header.Name)
		if !filepath.IsLocal(relative) {
			t.Fatal("nonlocal archive member")
		}
		target := filepath.Join(restored, relative)
		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(target, fs.FileMode(header.Mode)); err != nil {
				t.Fatal(err)
			}
			directories = append(directories, target)
		case tar.TypeReg:
			out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			n, copyErr := io.Copy(out, reader)
			modeErr := out.Chmod(fs.FileMode(header.Mode))
			syncErr, closeErr := out.Sync(), out.Close()
			if n != header.Size || copyErr != nil || modeErr != nil || syncErr != nil || closeErr != nil {
				t.Fatal("actual profile/source restore", copyErr, modeErr, syncErr, closeErr)
			}
		default:
			t.Fatal("unsupported native archive member")
		}
	}
	for _, entry := range b.entries {
		target := filepath.Join(restored, filepath.FromSlash(entry.Name))
		info, e := os.Lstat(target)
		if e != nil || info.IsDir() != entry.Directory || info.Mode().Perm() != entry.Mode {
			t.Fatal("restored native shape", e)
		}
		if !entry.Directory {
			digest, e := admissionFileDigest(target)
			if e != nil || digest != entry.SHA256 || info.Size() != entry.Bytes {
				t.Fatal("restored actual native bytes", e)
			}
		}
	}
	for i := len(directories) - 1; i >= 0; i-- {
		admissionDirectorySync(t, directories[i])
	}
	admissionDirectorySync(t, restored)
	admissionDirectorySync(t, directory)
	actualConfig, err := LoadConfig(filepath.Join(restored, "config.json"))
	if err != nil || !reflect.DeepEqual(actualConfig, cfg) {
		t.Fatal("actual product LoadConfig must read restored profile", err)
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(restored, "fixture-tls", "chain.pem"), filepath.Join(restored, "fixture-tls", "key.pem")); err != nil {
		t.Fatal("actual TLS private authority restore", err)
	}
	if _, err = os.Lstat(filepath.Join(restored, "state", "indexed", "sync-state.sqlite")); !os.IsNotExist(err) {
		t.Fatal("SQLite absence must be faithfully restored", err)
	}
	if !reflect.DeepEqual(b.before, nativeBulkPhysical(t, f)) {
		t.Fatal("local restore changed original inodes")
	}
	admissionProofWrite(t, filepath.Join(directory, "native-before.json"), map[string]any{"schema": "pluto.native-bulk-local-backup.v1", "case": t.Name(), "at": time.Now().UTC(), "requestID": b.requestID, "base": f.base, "state": f.state, "source": f.source, "config": f.config, "ca": f.ca, "archiveSHA256": b.archiveSHA, "entries": b.entries, "originalPhysical": b.before, "actualProductLoadConfig": true, "actualTLSKeyPairLoaded": true, "initialSQLiteAbsent": true, "nativeChildStarted": false, "relocatedLocalArtifactCustodyAdmitted": false, "ephemeralOwnerSocketRestored": false})
	return b
}
func qualifyNativeBulkCheckpoint(t *testing.T, f *cDaemonFixture, origin string) *nativeBulkLocalBackup {
	t.Helper()
	tier, err := strconv.Atoi(os.Getenv("ENDURANCE_TIER"))
	if err != nil || tier < 7 {
		t.Fatal("mandatory bulk lost-ACK fault requires explicit tier>=7", err)
	}
	b := nativeBulkArchive(t, f)
	tokenPath := os.Getenv("PLUTO_BULK_CHECKPOINT_TOKEN_FILE")
	info, err := os.Lstat(tokenPath)
	if err != nil || !filepath.IsAbs(tokenPath) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private owned checkpoint token file required", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		t.Fatal("exact private checkpoint credential owner required")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.TrimSpace(string(token))
	decoded, err := hex.DecodeString(credential)
	if err != nil || len(decoded) != 32 || len(credential) != 64 {
		t.Fatal("fresh32byte checkpoint credential required")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/" {
		t.Fatal("explicit owned isolated loopback backend control required", err)
	}
	beforeProofSHA, err := admissionFileDigest(filepath.Join(b.directory, "native-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"schema": "pluto.native-bulk-checkpoint-request.v1", "case": t.Name(), "requestID": b.requestID, "base": f.base, "state": f.state, "source": f.source, "config": f.config, "ca": f.ca, "nativeBackupDirectory": b.directory, "nativeArchiveSHA256": b.archiveSHA, "nativeChildStarted": false, "nativeBeforeSHA256": beforeProofSHA}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 1<<20 {
		t.Fatal("bounded genuine checkpoint request", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"__completion/checkpoint", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Bulk-Checkpoint-Token", credential)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("genuine complete backend checkpoint/restore prerequisite", err)
	}
	result, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(result) > 1<<20 {
		t.Fatal("owned checkpoint did not qualify", response.StatusCode, readErr, closeErr)
	}
	var proof nativeBulkCheckpointProof
	if err = json.Unmarshal(result, &proof); err != nil || proof.Schema != "pluto.native-bulk-checkpoint-proof.v1" || proof.Status != "PASS_GENUINE_FULL_GRAPH_RESTORE" || proof.RequestID != b.requestID || proof.NativeArchiveSHA256 != b.archiveSHA || len(proof.GraphSHA256) != 64 || !proof.PostgreSQLRestored || !proof.FullSQLRowsCompared || !proof.PhysicalSFTPRestored || !proof.AllPhysicalBytesCompared || !proof.ActualProductReadback || !proof.AuthorityConfigRestored || !proof.OriginalBackendStoppedReceipt || !proof.OriginalBackendResumed || proof.CanaryBytes <= 0 {
		t.Fatal("complete actual PG/SFTP/profile/authority restore required before fault", err)
	}
	if _, err = hex.DecodeString(proof.GraphSHA256); err != nil {
		t.Fatal("checkpoint graph fingerprint", err)
	}
	if !reflect.DeepEqual(b.before, nativeBulkPhysical(t, f)) {
		t.Fatal("backend checkpoint altered original native profiles/sources")
	}
	b.remote = append(json.RawMessage(nil), result...)
	admissionProofWrite(t, filepath.Join(b.directory, "full-graph-before-fault.json"), map[string]any{"schema": "pluto.native-bulk-before-fault.v1", "case": t.Name(), "at": time.Now().UTC(), "requestID": b.requestID, "nativeArchiveSHA256": b.archiveSHA, "nativeOriginalPhysicalUnchanged": true, "nativeChildStarted": false, "checkpoint": b.remote, "firstFaultAuthorizedOnlyAfterThisProof": true, "historicalReaderExecuted": false})
	t.Logf("NATIVE_BULK_FULL_GRAPH_RESTORE_QUALIFIED requestID=%s nativeSHA256=%s graphSHA256=%s directory=%s", b.requestID, b.archiveSHA, proof.GraphSHA256, b.directory)
	return b
}
func (b *nativeBulkLocalBackup) recordFinal(t *testing.T, f *cDaemonFixture, expected map[string]string, lostAck bool, count int) {
	t.Helper()
	if !lostAck || count < 8 || count > 4096 || len(expected) != count || len(b.remote) == 0 {
		t.Fatal("all original bulk/fault assertions must execute")
	}
	db := filepath.Join(f.state, "indexed", "sync-state.sqlite")
	for _, suffix := range []string{"-wal", "-journal"} {
		info, err := os.Stat(db + suffix)
		if err == nil && info.Size() != 0 {
			t.Fatal("joined normal daemon must checkpoint before final proof")
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	logical, rows := admissionLogicalDigest(t, db)
	digest, err := admissionFileDigest(db)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	if err = filepath.WalkDir(f.source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(f.source, p)
		if err != nil {
			return err
		}
		actual, err := admissionFileDigest(p)
		if err != nil {
			return err
		}
		if expected[filepath.ToSlash(relative)] != actual {
			return fmt.Errorf("actual final original source differs")
		}
		files++
		return nil
	}); err != nil || files != count {
		t.Fatal("exact final source files required", err)
	}
	admissionProofWrite(t, filepath.Join(b.directory, "native-after.json"), map[string]any{"schema": "pluto.native-bulk-local-result.v1", "case": t.Name(), "at": time.Now().UTC(), "requestID": b.requestID, "state": f.state, "source": f.source, "config": f.config, "ca": f.ca, "nativeArchiveSHA256": b.archiveSHA, "checkpoint": b.remote, "actualSourceFiles": files, "expectedFinal": expected, "profileSQLiteSHA256": digest, "profileLogicalSHA256": logical, "profileLogicalRows": rows, "finalPhysical": nativeBulkPhysical(t, f), "lostCommittedAckObserved": lostAck, "nativeDaemonJoinedBeforeProof": true, "historicalReaderExecuted": false, "fullCI": false})
	t.Logf("NATIVE_BULK_FINAL_LOCAL_QUALIFIED files=%d sqliteSHA256=%s directory=%s", files, digest, b.directory)
}
