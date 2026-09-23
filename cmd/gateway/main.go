// Command gateway runs llm-proxy: the proxied LLM API, the web API and metrics,
// each on its own listener. The composition lives in internal/boot.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/elleqt/llm-proxy-backend/internal/boot"
)

// version is set at build time: -ldflags "-X main.version=...".
var version string

func main() {
	if err := boot.Run(context.Background(), boot.Options{Output: os.Stderr, Version: version}); err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}
}
