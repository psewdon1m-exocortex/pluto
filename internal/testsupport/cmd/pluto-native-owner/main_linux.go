//go:build linux

package main

import (
	"fmt"
	"os"
	nativefixture "pluto/internal/testsupport/nativeprocess"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "native-owner requires exact Root manifest path and SHA")
		os.Exit(77)
	}
	owner, err := nativefixture.NewOwner(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "OWNER_ADMISSION_REFUSED", err)
		os.Exit(77)
	}
	// Run's loaded cleanup/reaper remains active until every owned Start has an
	// actual outcome and streams joined. No timeout-Kill or PID adoption path.
	os.Exit(owner.Run())
}
