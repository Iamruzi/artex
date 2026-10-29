// Package execution contains the host-owned subprocess lifecycle. Commands are
// bounded independently of how much output the child attempts to write.
package execution

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

const MaxOutput = 2 << 20

type boundedOutput struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := MaxOutput - b.buf.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return n, nil
}

func Run(ctx context.Context, cmd *exec.Cmd) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var out boundedOutput
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 2 * time.Second // inherited stdout pipes must not stall cleanup
	cleanup := contain(cmd)
	defer cleanup()
	err := cmd.Run()
	body := out.buf.String()
	if out.truncated {
		body += "\n[output truncated at 2 MiB]"
	}
	if ctx.Err() != nil {
		return body, fmt.Errorf("process interrupted: %w", ctx.Err())
	}
	if err != nil {
		return body, fmt.Errorf("process failed: %w", err)
	}
	return body, nil
}
