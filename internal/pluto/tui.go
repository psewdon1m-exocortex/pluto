package pluto

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func TUI(ctx context.Context, socket string, checkUpdate func(string) (string, error), applyUpdate func(string) error) error {
	defer func() { command := exec.Command("stty", "echo"); command.Stdin = os.Stdin; _ = command.Run() }()
	go func() {
		<-ctx.Done()
		command := exec.Command("stty", "echo")
		command.Stdin = os.Stdin
		_ = command.Run()
		_ = os.Stdin.Close()
	}()
	remote := Remote{LocalClient(socket), "http://localhost", ""}
	input := bufio.NewReader(os.Stdin)
	read := func(label string, secret bool) string {
		fmt.Print(label + ": ")
		if secret {
			cmd := exec.Command("stty", "-echo")
			cmd.Stdin = os.Stdin
			_ = cmd.Run()
		}
		line, _ := input.ReadString('\n')
		if secret {
			cmd := exec.Command("stty", "echo")
			cmd.Stdin = os.Stdin
			_ = cmd.Run()
			fmt.Println()
		}
		return strings.TrimSpace(line)
	}
	for {
		var status Status
		if err := remote.request(ctx, "GET", "/status", nil, -1, nil, &status); err != nil {
			return err
		}
		fmt.Print("\033[2J\033[H")
		fmt.Printf("PLUTO %s\nConnection: %s | Connected: %t | Copying: %t | Running: %t\nInterval: %d seconds\nLast success: %s\nError: %s\nSources:\n", status.Version, status.ConnectionName, status.Connected, status.Observation.Enabled, status.Running, status.Observation.IntervalSeconds, status.Observation.LastSuccessAt, status.Observation.Error)
		for _, source := range status.Sources {
			fmt.Println("  " + source)
		}
		fmt.Println("\n1 Kernel connection\n2 Files and folders\n3 Interval\n4 Paste Saturn setup code\n5 Enable/disable copying\n6 Copy now\n7 Check update\n8 Install update\n9 Disconnect locally\nq Exit")
		choice := read("Select", false)
		if choice == "q" || choice == "" {
			return nil
		}
		control := Control{}
		switch choice {
		case "1":
			control = Control{Action: "connect", KernelURL: read("Kernel HTTPS URL", false), Token: read("Outdoor service token", true)}
		case "2":
			fmt.Println("Enter one absolute path per line. Empty line completes the list.")
			for {
				v := read("Path", false)
				if v == "" {
					break
				}
				control.Sources = append(control.Sources, v)
			}
			control.Action = "sources"
		case "3":
			seconds, _ := strconv.Atoi(read("Interval in seconds (minimum 60)", false))
			control = Control{Action: "interval", IntervalSeconds: seconds}
		case "4":
			control = Control{Action: "enroll", Code: read("One-time Saturn setup code", true)}
		case "5":
			control = Control{Action: "enabled", Enabled: !status.Observation.Enabled}
		case "6":
			control = Control{Action: "run"}
		case "7":
			v, err := checkUpdate(status.Repository)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Println("Available version:", v)
			}
			read("Enter to continue", false)
			continue
		case "8":
			if read("Type UPDATE to install the verified release", false) == "UPDATE" {
				if err := applyUpdate(status.Repository); err != nil {
					fmt.Println(err)
				} else {
					return nil
				}
			}
			read("Enter to continue", false)
			continue
		case "9":
			control = Control{Action: "disconnect"}
		default:
			continue
		}
		if err := remote.json(ctx, "POST", "/control", control, nil); err != nil {
			fmt.Println("Action failed:", err)
			read("Enter to continue", false)
		}
	}
}
