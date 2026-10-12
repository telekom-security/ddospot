// Command ddospot runs the CHARGEN, DNS, NTP and SSDP honeypots. Settings
// come from the environment, see app.FromEnv; SIGTERM or SIGINT stops it.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/telekom-security/ddospot/internal/app"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	cfg, err := app.FromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ddospot:", err)
		return 1
	}
	if err := app.Run(ctx, cfg, nil); err != nil {
		fmt.Fprintln(os.Stderr, "ddospot:", err)
		return 1
	}
	return 0
}
