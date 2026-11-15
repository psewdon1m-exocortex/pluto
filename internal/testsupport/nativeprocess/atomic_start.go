package nativefixture

import "fmt"

// Used by the real owner. Registration precedes this function. The deferred
// installation is armed BEFORE Start and runs before post-Start metadata, also
// on a recovered panic. It never acquires a process by a caller-supplied PID.
func guardedStart(start func() error, hasOriginalHandle func() bool, installWait func()) (err error) {
	defer func() {
		if hasOriginalHandle() {
			installWait()
		}
		if p := recover(); p != nil {
			err = fmt.Errorf("typed Start panic retained: %v", p)
		}
	}()
	return start()
}
