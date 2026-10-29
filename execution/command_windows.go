//go:build windows

package execution

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func contain(cmd *exec.Cmd) func() {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		killCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		killer := exec.CommandContext(killCtx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
		killer.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		killer.WaitDelay = time.Second
		_ = killer.Run()
		return cmd.Process.Kill()
	}
	// Windows cancellation uses taskkill /T. Strict orphan/escape containment
	// requires a Job object or the supported Linux cgroup deployment boundary.
	return func() {}
}
