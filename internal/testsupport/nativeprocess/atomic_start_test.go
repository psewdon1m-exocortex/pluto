package nativefixture

import (
	"errors"
	"reflect"
	"testing"
)

func TestGuardedStartOwnsWaitBeforePostStartMetadata(t *testing.T) {
	for _, point := range []string{"success", "refused-before-fork", "panic-before-handle", "panic-after-handle"} {
		t.Run(point, func(t *testing.T) {
			order := []string{"reserved-before-Start"}
			handle := false
			waits := 0
			err := guardedStart(func() error {
				order = append(order, "typed-Start")
				if point == "refused-before-fork" {
					return errors.New("precondition")
				}
				if point == "panic-before-handle" {
					panic("before handle")
				}
				handle = true
				if point == "panic-after-handle" {
					panic("postfork reporter")
				}
				return nil
			}, func() bool { return handle }, func() { waits++; order = append(order, "original-handle-Wait-installed") })
			order = append(order, "post-Start-metadata")
			if (point == "success") != (err == nil) {
				t.Fatal(point, err)
			}
			if handle && waits != 1 || !handle && waits != 0 {
				t.Fatal("wrong Wait ownership", waits)
			}
			want := []string{"reserved-before-Start", "typed-Start"}
			if handle {
				want = append(want, "original-handle-Wait-installed")
			}
			want = append(want, "post-Start-metadata")
			if !reflect.DeepEqual(order, want) {
				t.Fatal(order, want)
			}
		})
	}
}

func TestOutcomeCannotBeInventedOrDeadlineErased(t *testing.T) {
	zero := Actual{PID: 23, Observed: true, Exited: true, ExitCode: 0}
	if got := lifecycleError(zero, false, false, true, true, true); got != "" {
		t.Fatal(got)
	}
	for _, change := range []string{"unknown", "ambiguous", "made-up137", "missing-numeric", "missing-drains", "deadline", "join-watchdog", "truncated"} {
		t.Run(change, func(t *testing.T) {
			a := zero
			numeric, drains, out := true, true, true
			deadline, watchdog := false, false
			switch change {
			case "unknown":
				a.Observed = false
			case "ambiguous":
				a.Signaled = true
			case "made-up137":
				a.Exited = false
				a.Signaled = true
				a.Signal = 9
				a.ExitCode = 137
			case "missing-numeric":
				numeric = false
			case "missing-drains":
				drains = false
			case "deadline":
				deadline = true
			case "join-watchdog":
				watchdog = true
			case "truncated":
				out = false
			}
			if lifecycleError(a, deadline, watchdog, numeric, drains, out) == "" {
				t.Fatal("false success", change)
			}
		})
	}
	signal := Actual{PID: 23, Observed: true, Signaled: true, ExitCode: -1, Signal: 9, RawStatus: 9}
	if lifecycleError(signal, false, false, true, true, true) != "" || domainError(signal) != "signal 9 raw=9" {
		t.Fatal(signal)
	}
}
