//go:build linux

package syncstate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	nf "pluto/internal/testsupport/nativeprocess"
)

type nativeCLIResult struct { PID int; Stdout,Stderr []byte; DomainError,LifecycleError error }
var nativeCLIScopes=struct{sync.Mutex;values map[string]*nf.Scope;registered map[string]bool}{values:map[string]*nf.Scope{},registered:map[string]bool{}}
func nativeFixtureSelected(t *testing.T) bool {n:=t.Name();return strings.HasPrefix(n,"TestSmallBatchEngineActualCLIProcessesMixedAndLostReply/")||strings.HasPrefix(n,"TestHTTPRebootstrapHistoricalSignedCLIRefusesBothInterruptedPhases/")||n=="TestOwnerMountActualSignedCLIOriginalRecoveryAndFresh"}
func nativeCLIScope(t *testing.T) *nf.Scope {
	t.Helper();nativeCLIScopes.Lock();defer nativeCLIScopes.Unlock();if s:=nativeCLIScopes.values[t.Name()];s!=nil{return s}
	c,e:=nf.ClientFromEnvironment();if e!=nil{t.Fatal(e)};s,e:=c.NewScope(t.Name());if e!=nil{t.Fatal(e)};nativeCLIScopes.values[t.Name()]=s;return s
}
func nativeFixtureTempDir(t *testing.T) string {t.Helper();if !nativeFixtureSelected(t){return t.TempDir()};p,e:=nativeCLIScope(t).TempDir();if e!=nil{t.Fatal(e)};return p}
func nativeFixtureRegisterCleanup(t *testing.T) {if !nativeFixtureSelected(t){return};s:=nativeCLIScope(t);nativeCLIScopes.Lock();if nativeCLIScopes.registered[t.Name()]{nativeCLIScopes.Unlock();return};nativeCLIScopes.registered[t.Name()]=true;nativeCLIScopes.Unlock();t.Cleanup(func(){if e:=s.Close();e!=nil{t.Error("native actual closure failed",e)}})}
func runNativeFixtureCLI(t *testing.T,ctx context.Context,role,binary,config,state string) nativeCLIResult {
	t.Helper();s:=nativeCLIScope(t);a,e:=s.Artifact(role);if e!=nil||a.Path!=binary{return nativeCLIResult{LifecycleError:errors.New("Root-admitted exact native role path required")}}
	if e=s.Bind(config,state,"");e!=nil{return nativeCLIResult{LifecycleError:e}}
	r:=s.Run(ctx,role,"copy-indexed","","");out:=nativeCLIResult{PID:r.Actual.PID,Stdout:r.Stdout,Stderr:r.Stderr};if r.DomainError!=""{out.DomainError=errors.New(r.DomainError)};if r.LifecycleError!=""{out.LifecycleError=errors.New(r.LifecycleError)};return out
}
