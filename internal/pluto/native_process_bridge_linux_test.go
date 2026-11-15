//go:build linux

package pluto

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	nf "pluto/internal/testsupport/nativeprocess"
)

type nativeFixtureScope struct { t *testing.T; scope *nf.Scope }
type nativeFixtureChild struct { owner *nativeFixtureScope; child *nf.Child; stopOnce sync.Once }
type nativeFixtureResult struct { Combined []byte; DomainError,LifecycleError error }
var nativeFixtureScopes = struct{sync.Mutex;values map[string]*nativeFixtureScope}{values:map[string]*nativeFixtureScope{}}

func nativeFixtureBase(t *testing.T) (string,*nativeFixtureScope) {
	t.Helper()
	if os.Getenv("COMPLETION_REUSE_BASE")!=""{t.Fatal("fresh Root-owned native fixture only; no old scope adoption")}
	client,err:=nf.ClientFromEnvironment();if err!=nil{t.Fatal(err)}
	scope,err:=client.NewScope(t.Name());if err!=nil{t.Fatal(err)}
	owned:=&nativeFixtureScope{t,scope}
	nativeFixtureScopes.Lock();if nativeFixtureScopes.values[t.Name()]!=nil{nativeFixtureScopes.Unlock();t.Fatal("one scope per native testcase")};nativeFixtureScopes.values[t.Name()]=owned;nativeFixtureScopes.Unlock()
	return scope.Base,owned
}
func newNativeFixtureScope(t *testing.T,binary,base,ca,config,state string) *nativeFixtureScope {
	t.Helper();nativeFixtureScopes.Lock();owned:=nativeFixtureScopes.values[t.Name()];nativeFixtureScopes.Unlock()
	if owned==nil||owned.scope.Base!=base{t.Fatal("fixture must originate from loaded owner before data creation")}
	artifact,err:=owned.scope.Artifact("current");if err!=nil||artifact.Path!=binary{t.Fatal("Root-admitted exact CLI path",err)}
	if err=owned.scope.Bind(config,state,ca);err!=nil{t.Fatal(err)}
	return owned
}
func nativeFixtureDeadline(t *testing.T,until time.Time) func() {nativeFixtureScopes.Lock();owned:=nativeFixtureScopes.values[t.Name()];nativeFixtureScopes.Unlock();if owned==nil{return func(){}};return owned.scope.PushDeadline(until)}
func (s *nativeFixtureScope) RunDomain(action string,args ...string) nativeFixtureResult {
	profile,digest:="",""
	for i:=0;i<len(args);i+=2{if i+1>=len(args){return nativeFixtureResult{LifecycleError:errors.New("typed fixture argument pairs")}};switch args[i]{case"--profile":profile=args[i+1];case"--plan-digest":digest=args[i+1];default:return nativeFixtureResult{LifecycleError:errors.New("unreviewed fixture argument")}}}
	r:=s.scope.Run(context.Background(),"domain",action,profile,digest)
	var life,domain error;if r.LifecycleError!=""{life=errors.New(r.LifecycleError)};if r.DomainError!=""{domain=errors.New(r.DomainError)}
	return nativeFixtureResult{r.Combined,domain,life}
}
func (s *nativeFixtureScope) StartDaemon() (*nativeFixtureChild,error) {c,e:=s.scope.Start(context.Background(),"daemon","daemon","","");if c==nil{return nil,e};return &nativeFixtureChild{owner:s,child:c},e}
func (s *nativeFixtureScope) StartAdoption(profile,digest string,release func()) (*nativeFixtureChild,error) {s.scope.RegisterRelease(release);c,e:=s.scope.Start(context.Background(),"adoption-fault","adopt",profile,digest);if c==nil{return nil,e};return &nativeFixtureChild{owner:s,child:c},e}
func (s *nativeFixtureScope) CloseAdmissionAndJoinAll(){if e:=s.scope.Close();e!=nil{s.t.Error("native real closure failed",e)}}
func (s *nativeFixtureScope) OwnGo(fn func()){if e:=s.scope.Go(fn);e!=nil{s.t.Fatal(e)}}
func (s *nativeFixtureScope) RunReviewedAuxiliaryCopy(mode,source,destination string) ([]byte,error){r:=s.scope.Copy(mode,source,destination);if r.LifecycleError!=""{return r.Combined,errors.New(r.LifecycleError)};if r.DomainError!=""{return r.Combined,errors.New(r.DomainError)};return r.Combined,nil}
func (c *nativeFixtureChild) FailDeadline(reason string){if e:=c.child.FailDeadline(reason);e!=nil{c.owner.t.Error("deadline receipt failed",e)}}
func (c *nativeFixtureChild) JoinActualDurable() nf.Result {r:=c.child.Join();if r.LifecycleError!=""||!r.NumericDurable||!r.DrainsJoined{c.owner.t.Error("native actual join/receipt failed",r.LifecycleError)};return r}
func (c *nativeFixtureChild) CrashExactReviewedSite(site string) error {r:=c.child.Crash(site,true);if r.LifecycleError!=""{return errors.New(r.LifecycleError)};if !r.Actual.Signaled||r.Actual.Signal!=9{return errors.New("explicit reviewed SIGKILL not observed")};return nil}
func (c *nativeFixtureChild) StopExactReviewedMode(crash bool) {
	c.stopOnce.Do(func(){
	var r nf.Result
	if crash{site:=nf.FaultSite(c.owner.t.Name());if site==""{c.owner.t.Error("unreviewed crash refused");return};r=c.child.Crash(site,true)}else{r=c.child.Stop()}
	if r.LifecycleError!=""||!r.NumericDurable||!r.DrainsJoined{c.owner.t.Error("native lifecycle/closure failed",r.LifecycleError);return}
	if crash {if !r.Actual.Signaled||r.Actual.Signal!=9{c.owner.t.Error("reviewed fault signal not observed",r.Actual)}}else if !r.Actual.Exited||r.Actual.ExitCode!=0{c.owner.t.Error("ordinary actual daemon outcome",r.Actual)}
	})
}
