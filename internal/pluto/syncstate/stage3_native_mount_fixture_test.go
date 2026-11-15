//go:build linux

package syncstate

// This helper is test-only. Normal go test keeps the direct native syscall
// contract. An authenticated disposable supervisor is opt-in and fails closed;
// it never simulates a mount or skips either mandatory native assertion.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const stage3NativeSelection = "^(TestStage3C02NativeUnmountGap|TestStage3C03NativeDiskFullPreservesCommit)$"

type stage3NativeMarker struct {
	Schema            string   `json:"schema"`
	Run               string   `json:"run"`
	Scope             string   `json:"scope"`
	Nonce             string   `json:"nonce"`
	ContainerID       string   `json:"container_id"`
	Created           string   `json:"created"`
	Image             string   `json:"image"`
	Prefix            string   `json:"prefix"`
	Base              string   `json:"base"`
	BasePythonSHA     string   `json:"base_python_sha256"`
	HelperPythonSHA   string   `json:"helper_python_sha256"`
	TestBinarySHA     string   `json:"test_binary_sha256"`
	SourceManifestSHA string   `json:"source_manifest_sha256"`
	GoArgv            []string `json:"go_argv"`
}

type stage3NativeIdentity struct {
	PID        int               `json:"pid"`
	PPID       int               `json:"ppid"`
	StartTicks uint64            `json:"start_ticks"`
	UID        []int             `json:"uid"`
	GID        []int             `json:"gid"`
	Groups     []int             `json:"groups"`
	Caps       map[string]uint64 `json:"caps"`
	NNP        int               `json:"nnp"`
	Seccomp    int               `json:"seccomp"`
}

type stage3NativeFrame struct {
	Run      string                `json:"run"`
	Scope    string                `json:"scope"`
	Nonce    string                `json:"nonce"`
	Op       string                `json:"op"`
	Seq      int                   `json:"seq"`
	Kind     string                `json:"kind,omitempty"`
	Target   string                `json:"target,omitempty"`
	MountID  int                   `json:"mount_id,omitempty"`
	Result   json.RawMessage       `json:"result,omitempty"`
	Identity *stage3NativeIdentity `json:"identity,omitempty"`
	GoTemp   string                `json:"go_temp,omitempty"`
	Exit     *int                  `json:"exit,omitempty"`
}

type stage3MountReceipt struct {
	Op    string `json:"op"`
	Kind  string `json:"kind"`
	Bytes int64  `json:"bytes"`
	Mount struct {
		ID      int    `json:"id"`
		Target  string `json:"target"`
		Type    string `json:"type"`
		Options string `json:"options"`
	} `json:"mount"`
	Removed int `json:"mount_id_removed"`
	Flags   int `json:"flags"`
}

type stage3NativeSession struct {
	marker stage3NativeMarker
	conn   *net.UnixConn
	frames chan stage3NativeFrame
	done   chan struct{}
	cancel context.CancelFunc
	ctx    context.Context
	seq    int
	root   string
	mu     sync.Mutex
}

var stage3Native *stage3NativeSession

func stage3NativeSelf() (stage3NativeIdentity, error) {
	var identity stage3NativeIdentity
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return identity, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	parse := func(key string) ([]int, error) {
		values := []int{}
		for _, value := range strings.Fields(fields[key]) {
			n, e := strconv.Atoi(value)
			if e != nil {
				return nil, e
			}
			values = append(values, n)
		}
		return values, nil
	}
	identity.UID, err = parse("Uid")
	if err != nil {
		return identity, err
	}
	identity.GID, err = parse("Gid")
	if err != nil {
		return identity, err
	}
	identity.Groups, err = parse("Groups")
	if err != nil {
		return identity, err
	}
	identity.Caps = map[string]uint64{}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		n, e := strconv.ParseUint(fields[key], 16, 64)
		if e != nil {
			return identity, e
		}
		identity.Caps[key] = n
		if n != 0 {
			return identity, fmt.Errorf("native test %s is nonzero", key)
		}
	}
	identity.PID, err = strconv.Atoi(fields["Pid"])
	if err != nil {
		return identity, err
	}
	identity.PPID, err = strconv.Atoi(fields["PPid"])
	if err != nil {
		return identity, err
	}
	identity.NNP, err = strconv.Atoi(fields["NoNewPrivs"])
	if err != nil {
		return identity, err
	}
	identity.Seccomp, err = strconv.Atoi(fields["Seccomp"])
	if err != nil {
		return identity, err
	}
	raw, err = os.ReadFile("/proc/self/stat")
	if err != nil {
		return identity, err
	}
	statFields := strings.Fields(string(raw)[strings.LastIndex(string(raw), ")")+2:])
	if len(statFields) < 20 {
		return identity, fmt.Errorf("short proc stat")
	}
	identity.StartTicks, err = strconv.ParseUint(statFields[19], 10, 64)
	if err != nil {
		return identity, err
	}
	if !reflect.DeepEqual(identity.UID, []int{10001, 10001, 10001, 10001}) || !reflect.DeepEqual(identity.GID, []int{10001, 10001, 10001, 10001}) || len(identity.Groups) != 0 || identity.PPID != 1 || identity.NNP != 1 || identity.Seccomp != 2 {
		return identity, fmt.Errorf("native test identity/NNP/parent refused: %+v", identity)
	}
	return identity, nil
}

func stage3NativeSHA(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", fmt.Errorf("bounded regular executable required")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, (64<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func stage3NativeOpen(markerPath string) (*stage3NativeSession, error) {
	info, err := os.Lstat(markerPath)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || owner.Uid != 0 || owner.Gid != 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("root-owned readonly bounded marker required")
	}
	raw, err := os.ReadFile(markerPath)
	if err != nil {
		return nil, err
	}
	var marker stage3NativeMarker
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&marker); err != nil {
		return nil, err
	}
	if len(marker.Nonce) != 64 || strings.Trim(marker.Nonce, "0123456789abcdef") != "" || marker.Schema != "native-mount-phase2.v1" || marker.Run != "release-candidate-20261102T192007Z-587ea6af" || marker.Scope != "PLUTO-NATIVE-MOUNT-PHASE2-"+marker.Nonce[:16] || marker.Prefix != "/exocortex-native-mount-p2-"+marker.Nonce[:16] || marker.Base != "/fixture-p2-"+marker.Nonce[:16] || markerPath != marker.Prefix+".json" || len(marker.ContainerID) != 64 {
		return nil, fmt.Errorf("scope/nonce/path marker refused")
	}
	host, err := os.Hostname()
	if err != nil || host != marker.ContainerID[:12] {
		return nil, fmt.Errorf("actual container hostname differs")
	}
	if _, err = os.Stat("/.dockerenv"); err != nil {
		return nil, err
	}
	created, err := time.Parse(time.RFC3339Nano, marker.Created)
	if err != nil || time.Since(created) < 0 || time.Since(created) > 3*time.Minute {
		return nil, fmt.Errorf("fresh created lease refused")
	}
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	actualSHA, err := stage3NativeSHA("/proc/self/exe")
	if err != nil || executable != marker.Prefix+".test" || actualSHA != marker.TestBinarySHA || !reflect.DeepEqual(os.Args, marker.GoArgv) {
		return nil, fmt.Errorf("actual after-exec binary/argv custody refused")
	}
	expected := []string{marker.Prefix + ".test", "-test.run=" + stage3NativeSelection, "-test.v", "-test.count=1", "-test.timeout=0"}
	if !reflect.DeepEqual(os.Args, expected) {
		return nil, fmt.Errorf("only exact two-test selection admitted")
	}
	fd, err := strconv.Atoi(os.Getenv("STAGE3_NATIVE_MOUNT_FD"))
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("owned socket fd required")
	}
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_SEQPACKET {
		return nil, fmt.Errorf("seqpacket required")
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "native-mount-owner")
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, fmt.Errorf("Unix connection required")
	}
	root, err := os.MkdirTemp(marker.Base+"/work", "go-"+marker.Nonce[:16]+"-")
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err = os.Chmod(root, 0711); err != nil {
		conn.Close()
		return nil, err
	}
	// The 0711 envelope carries only two mount directories. SQLite/test profiles
	// remain separate private0700 directories; SYS_ADMIN alone needs traversal.
	ctx, cancel := context.WithCancel(context.Background())
	session := &stage3NativeSession{marker: marker, conn: conn, frames: make(chan stage3NativeFrame, 1), done: make(chan struct{}), ctx: ctx, cancel: cancel, root: root}
	go session.readLoop()
	return session, nil
}

func (session *stage3NativeSession) readLoop() {
	defer close(session.done)
	defer session.cancel()
	for {
		raw, control := make([]byte, 4096), make([]byte, unix.CmsgSpace(unix.SizeofUcred))
		n, oob, flags, _, err := session.conn.ReadMsgUnix(raw, control)
		if err != nil {
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return
		}
		messages, err := unix.ParseSocketControlMessage(control[:oob])
		if err != nil || len(messages) != 1 {
			return
		}
		credentials, err := unix.ParseUnixCredentials(&messages[0])
		if err != nil || credentials.Pid != 1 || credentials.Uid != 0 {
			return
		}
		var frame stage3NativeFrame
		decoder := json.NewDecoder(strings.NewReader(string(raw[:n])))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&frame) != nil || frame.Run != session.marker.Run || frame.Scope != session.marker.Scope || frame.Nonce != session.marker.Nonce {
			return
		}
		if frame.Op == "STOP" {
			return
		}
		select {
		case session.frames <- frame:
		case <-session.ctx.Done():
			return
		}
	}
}

func (session *stage3NativeSession) send(frame stage3NativeFrame) error {
	frame.Run, frame.Scope, frame.Nonce = session.marker.Run, session.marker.Scope, session.marker.Nonce
	raw, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(raw) > 4096 {
		return fmt.Errorf("bounded native frame required")
	}
	_, err = session.conn.Write(raw)
	return err
}

func (session *stage3NativeSession) receive(op string, seq int) (stage3NativeFrame, error) {
	select {
	case frame := <-session.frames:
		if frame.Op != op || frame.Seq != seq {
			return frame, fmt.Errorf("native operation/sequence mismatch")
		}
		return frame, nil
	case <-session.ctx.Done():
		return stage3NativeFrame{}, fmt.Errorf("native owner STOP/EOF/refusal")
	case <-time.After(5 * time.Second):
		return stage3NativeFrame{}, fmt.Errorf("native RPC finite lease expired")
	}
}

func (session *stage3NativeSession) operation(op, kind, target string, mountID int) (stage3MountReceipt, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.seq++
	var receipt stage3MountReceipt
	if err := session.send(stage3NativeFrame{Op: op, Seq: session.seq, Kind: kind, Target: target, MountID: mountID}); err != nil {
		return receipt, err
	}
	frame, err := session.receive("RESULT", session.seq)
	if err != nil {
		return receipt, err
	}
	if err = json.Unmarshal(frame.Result, &receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func TestMain(main *testing.M) {
	marker := os.Getenv("STAGE3_NATIVE_MOUNT_MARKER")
	if marker == "" {
		os.Exit(main.Run())
	}
	session, err := stage3NativeOpen(marker)
	if err != nil {
		fmt.Fprintln(os.Stderr, "native mount admission:", err)
		os.Exit(77)
	}
	stage3Native = session
	identity, err := stage3NativeSelf()
	if err == nil {
		err = session.send(stage3NativeFrame{Op: "READY", Identity: &identity, GoTemp: session.root})
	}
	if err == nil {
		_, err = session.receive("RUN", 0)
	}
	if err != nil {
		session.conn.Close()
		session.cancel()
		<-session.done
		fmt.Fprintln(os.Stderr, "native mount ready gate:", err)
		os.Exit(77)
	}
	testContext = session.ctx
	code := main.Run()
	if err = session.send(stage3NativeFrame{Op: "DONE", Seq: session.seq + 1, Exit: &code}); err != nil && code == 0 {
		code = 77
	}
	session.conn.Close()
	session.cancel()
	<-session.done
	os.Exit(code)
}

type stage3NativeMountHandle struct {
	directory, kind string
	id              int
	closed          bool
}

func stage3NativeMount(t *testing.T, kind string) *stage3NativeMountHandle {
	t.Helper()
	size := "8m"
	expected := int64(8 << 20)
	name := "TestStage3C02NativeUnmountGap"
	if kind == "large" {
		size = "64m"
		expected = 64 << 20
		name = "TestStage3C03NativeDiskFullPreservesCommit"
	} else if kind != "small" {
		t.Fatal("unknown fixed native mount kind")
	}
	if t.Name() != name {
		t.Fatal("native mount kind/test mismatch")
	}
	handle := &stage3NativeMountHandle{kind: kind}
	if stage3Native == nil {
		handle.directory = t.TempDir()
		if err := unix.Mount("tmpfs", handle.directory, "tmpfs", 0, "size="+size); err != nil {
			t.Fatalf("native mount gate unavailable: %v", err)
		}
	} else {
		handle.directory = filepath.Join(stage3Native.root, kind)
		if err := os.Mkdir(handle.directory, 0700); err != nil {
			t.Fatal(err)
		}
		receipt, err := stage3Native.operation("MOUNT", kind, handle.directory, 0)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Op != "MOUNT" || receipt.Kind != kind || receipt.Bytes != expected || receipt.Mount.ID <= 0 || receipt.Mount.Target != handle.directory || receipt.Mount.Type != "tmpfs" {
			t.Fatal("real native mount receipt differs", receipt)
		}
		handle.id = receipt.Mount.ID
		var filesystem unix.Statfs_t
		if err = unix.Statfs(handle.directory, &filesystem); err != nil || filesystem.Type != unix.TMPFS_MAGIC || int64(filesystem.Blocks)*int64(filesystem.Bsize) != expected {
			t.Fatal("actual tmpfs size/type differs", filesystem, err)
		}
	}
	t.Cleanup(func() {
		if err := handle.unmount(); err != nil {
			t.Errorf("normal owned native unmount: %v", err)
		}
	})
	return handle
}

func (handle *stage3NativeMountHandle) unmount() error {
	if handle.closed {
		return nil
	}
	if stage3Native == nil {
		if err := unix.Unmount(handle.directory, 0); err != nil {
			return err
		}
	} else {
		receipt, err := stage3Native.operation("UNMOUNT", handle.kind, handle.directory, handle.id)
		if err != nil {
			return err
		}
		if receipt.Op != "UNMOUNT" || receipt.Kind != handle.kind || receipt.Removed != handle.id || receipt.Flags != 0 {
			return fmt.Errorf("normal unmount incarnation receipt differs: %+v", receipt)
		}
	}
	handle.closed = true
	return nil
}
