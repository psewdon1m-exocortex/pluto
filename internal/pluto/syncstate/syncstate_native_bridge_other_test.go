//go:build !linux

package syncstate

import (
	"context"
	"errors"
	"testing"
)

type nativeCLIResult struct { PID int; Stdout,Stderr []byte; DomainError,LifecycleError error }
func nativeFixtureTempDir(t *testing.T) string {return t.TempDir()}
func nativeFixtureRegisterCleanup(t *testing.T) {}
func runNativeFixtureCLI(t *testing.T,ctx context.Context,role,binary,config,state string) nativeCLIResult {return nativeCLIResult{LifecycleError:errors.New("selected Pluto actual native CLI qualification supports Linux only; no Unix-signal fallback")}}
