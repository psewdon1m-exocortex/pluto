package pluto

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func newTUIInput(file *os.File, output io.Writer) (*tuiInput, func(), error) {
	stty := func(args ...string) (string, error) {
		command := exec.Command("stty", args...)
		command.Stdin = file
		bytes, err := command.Output()
		return strings.TrimSpace(string(bytes)), err
	}
	saved, err := stty("-g")
	if errors.Is(err, exec.ErrNotFound) {
		return nil, func() {}, errors.New("TUI requires stty from coreutils to safely configure terminal input")
	}
	interactive := err == nil
	restore := func() {
		if interactive {
			_, _ = stty(saved)
		}
	}
	input := &tuiInput{reader: bufio.NewReader(file), output: output, interactive: interactive}
	input.mode = func(menu, secret bool) error {
		if !interactive {
			return nil
		}
		args := []string{saved}
		if menu {
			args = append(args, "-icanon", "-echo", "min", "1", "time", "0")
		} else if secret {
			args = append(args, "-echo")
		}
		_, err := stty(args...)
		if err != nil {
			return fmt.Errorf("configure terminal: %w", err)
		}
		return nil
	}
	fd := int(file.Fd())
	var check syscall.FdSet
	if fd < 0 || fd >= len(check.Bits)*64 {
		return nil, restore, errors.New("terminal file descriptor exceeds select limit")
	}
	input.wait = func(ctx context.Context, duration time.Duration) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var read syscall.FdSet
		read.Bits[fd/64] |= 1 << uint(fd%64)
		timeout := syscall.NsecToTimeval(duration.Nanoseconds())
		count, err := syscall.Select(fd+1, &read, nil, nil, &timeout)
		if errors.Is(err, syscall.EINTR) {
			return false, ctx.Err()
		}
		return count > 0, err
	}
	return input, restore, nil
}
