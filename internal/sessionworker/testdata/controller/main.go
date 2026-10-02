// The real acceptance controller is a separately stamped subprocess. It owns
// only authenticated worker IPC; native process/session/RPC/PTY state is not
// linked into this executable.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

var build = "unstamped"

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	dir := os.Args[1]
	raw, err := os.ReadFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		fatal(err)
	}
	var boot sessionworker.Bootstrap
	if err = json.Unmarshal(raw, &boot); err != nil {
		fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, "control.key"))
	if err != nil {
		fatal(err)
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	controller, err := sessionworker.DialOwnerController(ctx, dir, boot.Scope, key, build)
	cancel()
	if err != nil {
		fatal(err)
	}
	defer controller.Close()
	encoder := json.NewEncoder(os.Stdout)
	_ = encoder.Encode(map[string]any{"controllerBuild": build, "workerBuild": controller.WorkerBuild, "lease": controller.Lease})
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var req sessionworker.Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		response, err := controller.Call(ctx, req)
		cancel()
		if err != nil {
			response = sessionworker.Response{Error: err.Error()}
		}
		if err = encoder.Encode(response); err != nil {
			fatal(err)
		}
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
