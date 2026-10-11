package pluto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testTUIInput(keys string, output io.Writer) *tuiInput {
	return &tuiInput{reader: bufio.NewReader(strings.NewReader(keys)), output: output, interactive: true, mode: func(bool, bool) error { return nil }}
}

func TestArrowNavigationAddsAndRemovesSourcesThroughControlAPI(t *testing.T) {
	dir := t.TempDir()
	old, added := filepath.Join(dir, "old"), filepath.Join(dir, "added")
	for _, name := range []string{old, added} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewService(filepath.Join(dir, "config.json"), dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(context.Background(), Control{Action: "sources", Sources: []string{old}}); err != nil {
		t.Fatal(err)
	}
	var actions []Control
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/control" {
			var control Control
			if err := json.NewDecoder(r.Body).Decode(&control); err != nil {
				t.Error(err)
				http.Error(w, "invalid", 400)
				return
			}
			actions = append(actions, control)
			if err := s.Apply(r.Context(), control); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		json.NewEncoder(w).Encode(s.Status())
	}))
	defer server.Close()
	// Down/Right opens sources, Enter adds; Down/Enter removes the old source.
	// Left returns to the main menu, then q exits.
	keys := "\x1b[B\x1b[C\r" + added + "\n\n\x1b[B\r\r\x1b[Dq"
	var output bytes.Buffer
	err = runTUI(context.Background(), Remote{server.Client(), server.URL, ""}, testTUIInput(keys, &output), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 || actions[0].Action != "sources-add" || actions[1].Action != "sources-remove" {
		t.Fatalf("unexpected source actions: %+v", actions)
	}
	if !reflect.DeepEqual(s.Status().Sources, []string{added}) {
		t.Fatalf("wrong final sources: %v", s.Status().Sources)
	}
	if !strings.Contains(output.String(), old) || !strings.Contains(output.String(), added) || strings.Contains(output.String(), "Action failed") {
		t.Fatal("source menu lost existing paths or failed an action")
	}
}

func TestMenuArrowsWrapScrollAndSupportApplicationCursorMode(t *testing.T) {
	items := make([]string, 20)
	for i := range items {
		items[i] = "item"
	}
	for _, tc := range []struct {
		keys string
		want int
	}{
		{"\x1b[A\r", 19}, {"\x1bOB\x1bOC", 1}, {"\x1b[F\x1b[A\r", 18}, {"\x1b[B\x1b[H\r", 0}, {"\x1b[D", -1}, {"\x1b", -1},
	} {
		selected := 0
		var output bytes.Buffer
		choice, err := testTUIInput(tc.keys, &output).choose(context.Background(), func() {}, items, &selected)
		if err != nil || choice != tc.want {
			t.Fatalf("keys %q: %d %v", tc.keys, choice, err)
		}
		if choice == 19 && !strings.Contains(output.String(), "> 20 item") {
			t.Fatal("selected item scrolled off screen")
		}
	}
}

func TestTerminalInputCancellationEOFAndControlText(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	input := testTUIInput("\r", io.Discard)
	if _, err := input.key(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
	input = testTUIInput("unfinished", io.Discard)
	if _, err := input.read(context.Background(), "Path", false); !errors.Is(err, io.EOF) {
		t.Fatal("accepted unfinished input", err)
	}
	if got := terminalText("name\x1b[2J\n\u202esecret"); strings.ContainsAny(got, "\x1b\n\u202e") {
		t.Fatalf("terminal control injection: %q", got)
	}
}

func TestNumberedMenusWithPipedInput(t *testing.T) {
	input := testTUIInput("2\nq\n", io.Discard)
	input.interactive = false
	selected := 0
	items := []string{"first", "second", "Back"}
	choice, err := input.choose(context.Background(), func() {}, items, &selected)
	if err != nil || choice != 1 {
		t.Fatalf("numbered selection: %d %v", choice, err)
	}
	choice, err = input.choose(context.Background(), func() {}, items, &selected)
	if err != nil || choice != -1 {
		t.Fatalf("numbered return: %d %v", choice, err)
	}
}

func TestEmptySourceAdditionCancelsWithoutControlRequest(t *testing.T) {
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			mutated = true
		}
		json.NewEncoder(w).Encode(Status{Sources: []string{"/existing"}})
	}))
	defer server.Close()
	input := testTUIInput("\r\nq", io.Discard)
	if err := input.sources(context.Background(), Remote{server.Client(), server.URL, ""}); err != nil {
		t.Fatal(err)
	}
	if mutated {
		t.Fatal("empty addition changed the old list")
	}
}
