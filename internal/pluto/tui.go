package pluto

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type tuiInput struct {
	reader      *bufio.Reader
	output      io.Writer
	interactive bool
	mode        func(menu, secret bool) error
	wait        func(context.Context, time.Duration) (bool, error)
}

var errKeyTimeout = errors.New("key timeout")

func terminalText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, value)
}

func (t *tuiInput) byte(ctx context.Context, timeout time.Duration) (byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if t.reader.Buffered() == 0 && t.wait != nil {
			delay := timeout
			if delay == 0 {
				delay = 100 * time.Millisecond
			}
			ready, err := t.wait(ctx, delay)
			if err != nil {
				return 0, err
			}
			if !ready {
				if timeout > 0 {
					return 0, errKeyTimeout
				}
				continue
			}
		}
		return t.reader.ReadByte()
	}
}

func (t *tuiInput) read(ctx context.Context, label string, secret bool) (string, error) {
	if err := t.mode(false, secret); err != nil {
		return "", err
	}
	defer t.mode(false, false)
	fmt.Fprint(t.output, label+": ")
	var line strings.Builder
	for {
		b, err := t.byte(ctx, 0)
		if err != nil {
			return "", err
		}
		if b == '\n' {
			if secret {
				fmt.Fprintln(t.output)
			}
			return strings.TrimSpace(line.String()), nil
		}
		if line.Len() >= 65536 {
			return "", errors.New("terminal input exceeds limit")
		}
		line.WriteByte(b)
	}
}

func (t *tuiInput) key(ctx context.Context) (string, error) {
	b, err := t.byte(ctx, 0)
	if err != nil {
		return "", err
	}
	if b == '\r' || b == '\n' {
		return "enter", nil
	}
	if b == 4 {
		return "back", nil
	}
	if b != 27 {
		return string(b), nil
	}
	b, err = t.byte(ctx, 100*time.Millisecond)
	if errors.Is(err, errKeyTimeout) || errors.Is(err, io.EOF) {
		return "back", nil
	}
	if err != nil {
		return "", err
	}
	if b != '[' && b != 'O' {
		return "", nil
	}
	for i := 0; i < 16; i++ {
		b, err = t.byte(ctx, 100*time.Millisecond)
		if errors.Is(err, errKeyTimeout) || errors.Is(err, io.EOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if b >= 0x40 && b <= 0x7e {
			switch b {
			case 'A':
				return "up", nil
			case 'B':
				return "down", nil
			case 'C':
				return "enter", nil
			case 'D':
				return "back", nil
			case 'H':
				return "home", nil
			case 'F':
				return "end", nil
			}
			return "", nil
		}
	}
	return "", nil
}

func (t *tuiInput) choose(ctx context.Context, render func(), items []string, selected *int) (int, error) {
	if err := t.mode(t.interactive, false); err != nil {
		return -1, err
	}
	defer t.mode(false, false)
	if *selected < 0 || *selected >= len(items) {
		*selected = 0
	}
	for {
		fmt.Fprint(t.output, "\033[2J\033[H")
		render()
		start := 0
		if *selected >= 12 {
			start = *selected - 11
		}
		if start > 0 {
			fmt.Fprintf(t.output, "  ... %d more above\n", start)
		}
		end := min(len(items), start+12)
		for i := start; i < end; i++ {
			marker := " "
			if i == *selected {
				marker = ">"
			}
			fmt.Fprintf(t.output, "%s %d %s\n", marker, i+1, terminalText(items[i]))
		}
		if end < len(items) {
			fmt.Fprintf(t.output, "  ... %d more below\n", len(items)-end)
		}
		var key string
		var err error
		if t.interactive {
			fmt.Fprintln(t.output, "\nUp/Down: move | Enter/Right: select | Esc/Left/q: back | 1-9: shortcut")
			key, err = t.key(ctx)
		} else {
			key, err = t.read(ctx, "Select number (q to go back)", false)
		}
		if err != nil {
			return -1, err
		}
		switch key {
		case "up", "k":
			*selected = (*selected + len(items) - 1) % len(items)
		case "down", "j":
			*selected = (*selected + 1) % len(items)
		case "home":
			*selected = 0
		case "end":
			*selected = len(items) - 1
		case "enter":
			return *selected, nil
		case "back", "q", "Q":
			return -1, nil
		default:
			number, parseErr := strconv.Atoi(key)
			if parseErr == nil && number >= 1 && number <= len(items) {
				*selected = number - 1
				return *selected, nil
			}
		}
	}
}

func (t *tuiInput) action(ctx context.Context, remote Remote, control Control) error {
	if err := remote.json(ctx, "POST", "/control", control, nil); err != nil {
		fmt.Fprintln(t.output, "Action failed:", terminalText(err.Error()))
		_, readErr := t.read(ctx, "Enter to continue", false)
		return readErr
	}
	return nil
}

func (t *tuiInput) sources(ctx context.Context, remote Remote) error {
	selected := 0
	for {
		var status Status
		if err := remote.request(ctx, "GET", "/status", nil, -1, nil, &status); err != nil {
			return err
		}
		choice, err := t.choose(ctx, func() {
			fmt.Fprintf(t.output, "Files and folders (%d/128)\nExisting sources are kept when adding paths.\n", len(status.Sources))
			for i, source := range status.Sources {
				if i == 8 {
					fmt.Fprintf(t.output, "  ... %d more (see Remove a source)\n", len(status.Sources)-i)
					break
				}
				fmt.Fprintln(t.output, "  "+terminalText(source))
			}
			fmt.Fprintln(t.output)
		}, []string{"Add files or folders", "Remove a source", "Back"}, &selected)
		if err != nil || choice < 0 || choice == 2 {
			return err
		}
		control := Control{}
		if choice == 0 {
			fmt.Fprintln(t.output, "Enter new absolute paths, one per line. Empty line saves additions; no paths cancels.")
			control.Action = "sources-add"
			for {
				value, err := t.read(ctx, "Path", false)
				if err != nil {
					return err
				}
				if value == "" {
					break
				}
				control.Sources = append(control.Sources, value)
				if len(control.Sources) > 128 {
					break
				}
			}
			if len(control.Sources) == 0 {
				continue
			}
		} else {
			items := append(append([]string{}, status.Sources...), "Back")
			removeSelected := 0
			index, err := t.choose(ctx, func() {
				fmt.Fprint(t.output, "Remove from future copying\nEnter removes the selected source. Stored backup files are kept.\n\n")
			}, items, &removeSelected)
			if err != nil {
				return err
			}
			if index < 0 || index == len(status.Sources) {
				continue
			}
			control = Control{Action: "sources-remove", Sources: []string{status.Sources[index]}}
		}
		if err := t.action(ctx, remote, control); err != nil {
			return err
		}
	}
}

func TUI(ctx context.Context, socket string, checkUpdate func(string) (string, error), applyUpdate func(string) error) error {
	input, restore, err := newTUIInput(os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	defer restore()
	err = runTUI(ctx, Remote{LocalClient(socket), "http://localhost", ""}, input, checkUpdate, applyUpdate)
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func runTUI(ctx context.Context, remote Remote, input *tuiInput, checkUpdate func(string) (string, error), applyUpdate func(string) error) error {
	selected := 0
	read := func(label string, secret bool) (string, error) { return input.read(ctx, label, secret) }
	for {
		var status Status
		if err := remote.request(ctx, "GET", "/status", nil, -1, nil, &status); err != nil {
			return err
		}
		choice, err := input.choose(ctx, func() {
			fmt.Fprintf(input.output, "PLUTO %s\nConnection: %s | Connected: %t | Copying: %t | Running: %t\nInterval: %d seconds\nLast success: %s\nError: %s\nSources: %d\n\n", terminalText(status.Version), terminalText(status.ConnectionName), status.Connected, status.Observation.Enabled, status.Running, status.Observation.IntervalSeconds, terminalText(status.Observation.LastSuccessAt), terminalText(status.Observation.Error), len(status.Sources))
		}, []string{"Kernel connection", "Files and folders", "Interval", "Paste Saturn setup code", "Enable/disable copying", "Copy now", "Check update", "Install update", "Disconnect locally", "Exit"}, &selected)
		if err != nil || choice < 0 || choice == 9 {
			return err
		}
		control := Control{}
		switch choice {
		case 0:
			origin, err := read("Kernel HTTPS URL", false)
			if err != nil {
				return err
			}
			token, err := read("Outdoor service token", true)
			if err != nil {
				return err
			}
			control = Control{Action: "connect", KernelURL: origin, Token: token}
		case 1:
			if err := input.sources(ctx, remote); err != nil {
				return err
			}
			continue
		case 2:
			value, err := read("Interval in seconds (minimum 60)", false)
			if err != nil {
				return err
			}
			seconds, _ := strconv.Atoi(value)
			control = Control{Action: "interval", IntervalSeconds: seconds}
		case 3:
			code, err := read("One-time Saturn setup code", true)
			if err != nil {
				return err
			}
			control = Control{Action: "enroll", Code: code}
		case 4:
			control = Control{Action: "enabled", Enabled: !status.Observation.Enabled}
		case 5:
			control = Control{Action: "run"}
		case 6:
			version, err := checkUpdate(status.Repository)
			if err != nil {
				fmt.Fprintln(input.output, terminalText(err.Error()))
			} else {
				fmt.Fprintln(input.output, "Available version:", terminalText(version))
			}
			if _, err := read("Enter to continue", false); err != nil {
				return err
			}
			continue
		case 7:
			confirmation, err := read("Type UPDATE to install the verified release", false)
			if err != nil {
				return err
			}
			if confirmation == "UPDATE" {
				if err := applyUpdate(status.Repository); err != nil {
					fmt.Fprintln(input.output, terminalText(err.Error()))
				} else {
					return nil
				}
			}
			if _, err := read("Enter to continue", false); err != nil {
				return err
			}
			continue
		case 8:
			control = Control{Action: "disconnect"}
		}
		if err := input.action(ctx, remote, control); err != nil {
			return err
		}
	}
}
