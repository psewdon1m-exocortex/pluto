package pluto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCopiesLetsEncryptFileLinksAtTheirOriginalPaths(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "letsencrypt", "live", "example.test")
	archive := filepath.Join(dir, "letsencrypt", "archive", "example.test")
	for _, path := range []string{live, archive} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"cert", "chain", "fullchain", "privkey"} {
		if err := os.WriteFile(filepath.Join(archive, name+"1.pem"), []byte("fixture-"+name), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../archive/example.test/"+name+"1.pem", filepath.Join(live, name+".pem")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ValidateSources([]string{live, filepath.Join(live, "cert.pem")}); err != nil {
		t.Fatal(err)
	}
	remote := Remote{f.server.Client(), f.server.URL, strings.Repeat("t", 43)}
	spool := filepath.Join(dir, "spool")
	count, err := Copy(context.Background(), remote, []string{live, filepath.Join(live, "cert.pem")}, spool)
	if err != nil || count != 4 {
		t.Fatalf("live links: %d %v", count, err)
	}
	for _, name := range []string{"cert", "chain", "fullchain", "privkey"} {
		if string(f.files[RelativePath(filepath.Join(live, name+".pem"))]) != "fixture-"+name {
			t.Fatalf("lost %s contents or original path", name)
		}
		if _, exists := f.files[RelativePath(filepath.Join(archive, name+"1.pem"))]; exists {
			t.Fatal("uploaded target under archive path")
		}
	}
	count, err = Copy(context.Background(), remote, []string{live}, spool)
	if err != nil || count != 0 {
		t.Fatalf("unchanged link targets uploaded: %d %v", count, err)
	}
	if err := os.WriteFile(filepath.Join(archive, "cert2.pem"), []byte("renewed-cert"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(live, "cert.pem")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../archive/example.test/cert2.pem", link); err != nil {
		t.Fatal(err)
	}
	count, err = Copy(context.Background(), remote, []string{live}, spool)
	if err != nil || count != 1 || string(f.files[RelativePath(link)]) != "renewed-cert" {
		t.Fatalf("renewed link: %d %v", count, err)
	}
	entries, err := os.ReadDir(spool)
	if err != nil || len(entries) != 0 {
		t.Fatal("link copy left plaintext spool", err)
	}
}

func TestUnsafeLinksReportPartialFailureAndKeepHealthyFiles(t *testing.T) {
	f := fixture(t)
	dir := t.TempDir()
	sources := filepath.Join(dir, "sources")
	outside := filepath.Join(dir, "outside")
	for _, path := range []string{sources, outside} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sources, "healthy"), []byte("healthy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "hidden"), []byte("hidden"), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(outside, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{"directory": outside, "fifo": fifo, "broken": filepath.Join(outside, "missing"), "loop": filepath.Join(sources, "loop")}
	for name, target := range links {
		link := filepath.Join(sources, name)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateSources([]string{link}); err == nil {
			t.Fatalf("accepted unsafe source: %s", name)
		}
	}
	count, err := Copy(context.Background(), Remote{f.server.Client(), f.server.URL, strings.Repeat("t", 43)}, []string{sources}, filepath.Join(dir, "spool"))
	if count != 1 || err == nil || !strings.Contains(err.Error(), "4 source entries failed") {
		t.Fatalf("unsafe links blocked healthy copy or were ignored: %d %v", count, err)
	}
	if len(f.files) != 1 || string(f.files[RelativePath(filepath.Join(sources, "healthy"))]) != "healthy" {
		t.Fatal("followed unsafe link or lost healthy file")
	}
}

func TestFileLinksRespectServiceAccountPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as an unprivileged account to exercise file permissions")
	}
	f := fixture(t)
	dir := t.TempDir()
	sources := filepath.Join(dir, "sources")
	if err := os.Mkdir(sources, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(target, []byte("fixture-key"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sources, "privkey.pem")); err != nil {
		t.Fatal(err)
	}
	healthy := filepath.Join(sources, "healthy.conf")
	if err := os.WriteFile(healthy, []byte("healthy"), 0600); err != nil {
		t.Fatal(err)
	}
	count, err := Copy(context.Background(), Remote{f.server.Client(), f.server.URL, strings.Repeat("t", 43)}, []string{sources}, filepath.Join(dir, "spool"))
	if count != 1 || err == nil || !strings.Contains(err.Error(), "Pluto service account") {
		t.Fatalf("missing permission failure: %d %v", count, err)
	}
	if len(f.files) != 1 || string(f.files[RelativePath(healthy)]) != "healthy" {
		t.Fatal("read inaccessible key or lost healthy file")
	}
}
