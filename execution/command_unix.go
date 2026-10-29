//go:build !windows

package execution

import (
	"os"
	"os/exec"
	"syscall"
)

func contain(cmd *exec.Cmd) func() {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	kill := func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.Cancel = kill
	return func() { _ = kill() }
}
