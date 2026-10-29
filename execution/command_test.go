package execution

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestProcessHelper(t *testing.T) {
	switch os.Getenv("ARTEX_PROCESS_TEST") {
	case "fail":
		os.Stdout.WriteString("partial evidence")
		os.Exit(7)
	case "large":
		os.Stdout.WriteString(strings.Repeat("x", MaxOutput+5000))
		os.Exit(0)
	case "wait":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
}

func helper(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessHelper$")
	cmd.Env = append(os.Environ(), "ARTEX_PROCESS_TEST="+mode)
	return cmd
}
func TestNonzeroExitAndOutputBudget(t *testing.T) {
	ctx := context.Background()
	out, e := Run(ctx, helper(ctx, "fail"))
	if e == nil || !strings.Contains(out, "partial evidence") {
		t.Fatalf("lost exit failure/output %q %v", out, e)
	}
	out, e = Run(ctx, helper(ctx, "large"))
	if e != nil || len(out) > MaxOutput+100 || !strings.Contains(out, "truncated") {
		t.Fatalf("unbounded output %d %v", len(out), e)
	}
}
func TestTimeoutAndPrecancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := Run(ctx, helper(ctx, "wait"))
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("lost deadline: %v", e)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("subprocess did not stop promptly")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, e = Run(ctx2, helper(ctx2, "wait"))
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
