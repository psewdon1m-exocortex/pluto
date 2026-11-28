package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"pluto/internal/pluto"
	"runtime"
	"syscall"
)

var Version = "0.1.5"
var ReleasePublicKey = ""

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--writer-schema" {
		json.NewEncoder(os.Stdout).Encode(pluto.IndexedWriterCompatibility())
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(Version)
		return
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Pluto supports Linux only")
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "licenses" {
		archive := len(os.Args) == 3 && os.Args[2] == "--archive"
		if len(os.Args) != 2 && !archive {
			fmt.Fprintln(os.Stderr, "Usage: pluto licenses [--archive]")
			os.Exit(2)
		}
		if err := pluto.WriteRuntimeLicenses(os.Stdout, archive); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: pluto daemon|tui|status|update|licenses|copy-indexed|inspect|diagnostics|pause|resume|checkpoint|backup|restore-artifact-directory|source-recover-plan|source-recover-apply|migrate-plan|adopt|policy-plan|policy-apply|namespace-plan|namespace-apply")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("pluto", flag.ExitOnError)
	config := flags.String("config", "/etc/pluto/config.json", "Protected configuration")
	state := flags.String("state", "/var/lib/pluto", "Protected state")
	socket := flags.String("socket", "/run/pluto/control.sock", "Local admin socket")
	profile := flags.String("profile", "", "Protected indexed profile candidate for migration")
	planDigest := flags.String("plan-digest", "", "Exact digest printed by the reviewed plan command")
	backupSHA := flags.String("backup-sha256", "", "Exact SHA-256 of the restored standalone SQLite backup")
	sourceID := flags.String("source-id", "", "Exact configured source ID for reviewed incarnation recovery")
	flags.Parse(os.Args[2:])
	if os.Args[1] == "source-recover-plan" || os.Args[1] == "source-recover-apply" {
		provided := map[string]bool{}
		flags.Visit(func(f *flag.Flag) { provided[f.Name] = true })
		if !provided["config"] || !provided["state"] || !provided["source-id"] || *sourceID == "" || flags.NArg() != 0 || os.Args[1] == "source-recover-apply" && (!provided["plan-digest"] || *planDigest == "") {
			fmt.Fprintln(os.Stderr, "source recovery requires explicit --config, --state, --source-id and an exact --plan-digest for apply")
			os.Exit(2)
		}
	}
	if os.Args[1] == "copy-indexed" || os.Args[1] == "restore-artifact-directory" {
		provided := map[string]bool{}
		flags.Visit(func(f *flag.Flag) { provided[f.Name] = true })
		if os.Args[1] == "copy-indexed" && (!provided["config"] || !provided["state"] || provided["socket"] || flags.NArg() != 0) {
			fmt.Fprintln(os.Stderr, "copy-indexed requires explicit --config and --state for a qualified isolated profile")
			os.Exit(2)
		}
		if os.Args[1] == "restore-artifact-directory" && (!provided["config"] || !provided["state"] || !provided["backup-sha256"] || flags.NArg() != 0) {
			fmt.Fprintln(os.Stderr, "restore-artifact-directory requires explicit --config, --state and --backup-sha256")
			os.Exit(2)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var err error
	check := func(repository string) (string, error) {
		release, e := pluto.CheckRelease(ctx, repository, ReleasePublicKey)
		return release.Version, e
	}
	update := func(repository string) error { return pluto.Update(ctx, repository, ReleasePublicKey, *socket) }
	switch os.Args[1] {
	case "source-recover-plan", "source-recover-apply":
		err = pluto.RunSourceRecoveryCommand(ctx, os.Args[1], *config, *state, *sourceID, *planDigest, os.Stdout)
	case "restore-artifact-directory":
		err = pluto.RunArtifactRestoreCommand(ctx, *config, *state, *backupSHA, os.Stdout)
	case "policy-plan", "policy-apply", "namespace-plan", "namespace-apply":
		err = pluto.RunPolicyCommand(ctx, os.Args[1], *config, *state, *profile, *planDigest, os.Stdout)
	case "inspect", "diagnostics", "pause", "resume", "checkpoint", "backup", "migrate-plan", "adopt":
		err = pluto.RunLifecycleCommand(ctx, os.Args[1], *config, *state, *socket, *profile, *planDigest, os.Stdout)
	case "copy-indexed":
		err = pluto.RunIndexedCommand(ctx, *config, *state, os.Stdout)
	case "daemon":
		var service *pluto.Service
		service, err = pluto.NewService(*config, *state, Version)
		if err == nil {
			err = service.Serve(ctx, *socket)
		}
	case "tui":
		err = pluto.TUI(ctx, *socket, check, update)
	case "status":
		client := pluto.LocalClient(*socket)
		var response *os.File
		response = os.Stdout
		resp, e := client.Get("http://localhost/status")
		err = e
		if err == nil {
			defer resp.Body.Close()
			_, err = response.ReadFrom(resp.Body)
		}
	case "update":
		var service *pluto.Service
		service, err = pluto.NewService(*config, *state, Version)
		if err == nil {
			err = update(service.Config.ReleaseRepository)
		}
	default:
		err = fmt.Errorf("unknown Pluto command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
