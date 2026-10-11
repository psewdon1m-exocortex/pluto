package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"pluto/internal/pluto"
	"runtime"
	"syscall"
)

var Version = "0.1.3"
var ReleasePublicKey = ""

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(Version)
		return
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "Pluto supports Linux only")
		os.Exit(1)
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: pluto daemon|tui|status|update")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("pluto", flag.ExitOnError)
	config := flags.String("config", "/etc/pluto/config.json", "Protected configuration")
	state := flags.String("state", "/var/lib/pluto", "Protected state")
	socket := flags.String("socket", "/run/pluto/control.sock", "Local admin socket")
	flags.Parse(os.Args[2:])
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var err error
	check := func(repository string) (string, error) {
		release, e := pluto.CheckRelease(ctx, repository, ReleasePublicKey)
		return release.Version, e
	}
	update := func(repository string) error { return pluto.Update(ctx, repository, ReleasePublicKey, *socket) }
	switch os.Args[1] {
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
