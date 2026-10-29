//go:build linux

package resourceguard

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type hostSampler struct {
	path        string
	total, idle uint64
	primed      bool
}

func NewSampler(dataDir string) Sampler { return &hostSampler{path: dataDir} }

func (h *hostSampler) Sample(ctx context.Context) (Sample, error) {
	if err := ctx.Err(); err != nil {
		return Sample{}, err
	}
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return Sample{}, err
	}
	total, idle, err := parseCPU(string(b))
	if err != nil {
		return Sample{}, err
	}
	oldTotal, oldIdle, primed := h.total, h.idle, h.primed
	h.total, h.idle, h.primed = total, idle, true
	if !primed || total <= oldTotal || idle < oldIdle || idle-oldIdle > total-oldTotal {
		return Sample{}, fmt.Errorf("等待 CPU 差分采样")
	}
	s := Sample{At: time.Now().UTC(), CPUPercent: 100 * (1 - float64(idle-oldIdle)/float64(total-oldTotal))}
	b, err = os.ReadFile("/proc/meminfo")
	if err != nil {
		return Sample{}, err
	}
	s.MemoryTotal, s.MemoryAvailable, err = parseMemory(string(b))
	if err != nil {
		return Sample{}, err
	}
	// Examine every visible cgroup ancestor: a child can say 'max' while its
	// parent (container/systemd slice) imposes the effective limit.
	if b, err = os.ReadFile("/proc/self/cgroup"); err == nil {
		applyCgroups(&s, "/sys/fs/cgroup", string(b))
	}
	s.MemoryPercent = 100 * (1 - float64(s.MemoryAvailable)/float64(s.MemoryTotal))
	var stat unix.Statfs_t
	if err = unix.Statfs(h.path, &stat); err != nil {
		return Sample{}, err
	}
	s.DiskTotal, s.DiskFree = stat.Blocks*uint64(stat.Bsize), stat.Bavail*uint64(stat.Bsize)
	return s, nil
}
