//go:build windows

package resourceguard

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var systemTimes = kernel.NewProc("GetSystemTimes")
var memoryStatus = kernel.NewProc("GlobalMemoryStatusEx")

type hostSampler struct {
	path        string
	total, idle uint64
	primed      bool
}

func NewSampler(dataDir string) Sampler { return &hostSampler{path: dataDir} }
func ticks(f windows.Filetime) uint64   { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

func (h *hostSampler) Sample(ctx context.Context) (Sample, error) {
	if e := ctx.Err(); e != nil {
		return Sample{}, e
	}
	var idle, kernelTime, user windows.Filetime
	r, _, e := systemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernelTime)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return Sample{}, fmt.Errorf("GetSystemTimes: %v", e)
	}
	total, i := ticks(kernelTime)+ticks(user), ticks(idle)
	ot, oi, primed := h.total, h.idle, h.primed
	h.total, h.idle, h.primed = total, i, true
	if !primed || total <= ot || i < oi || i-oi > total-ot {
		return Sample{}, fmt.Errorf("等待 CPU 差分采样")
	}
	var mem struct {
		Length, Load                                                                                         uint32
		TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual uint64
	}
	mem.Length = uint32(unsafe.Sizeof(mem))
	r, _, e = memoryStatus.Call(uintptr(unsafe.Pointer(&mem)))
	if r == 0 {
		return Sample{}, fmt.Errorf("GlobalMemoryStatusEx: %v", e)
	}
	s := Sample{At: time.Now().UTC(), CPUPercent: 100 * (1 - float64(i-oi)/float64(total-ot)), MemoryTotal: mem.TotalPhys, MemoryAvailable: mem.AvailPhys}
	if s.MemoryTotal == 0 {
		return Sample{}, fmt.Errorf("无效内存采样")
	}
	s.MemoryPercent = 100 * (1 - float64(s.MemoryAvailable)/float64(s.MemoryTotal))
	p, e := windows.UTF16PtrFromString(h.path)
	if e != nil {
		return Sample{}, e
	}
	if e = windows.GetDiskFreeSpaceEx(p, &s.DiskFree, &s.DiskTotal, nil); e != nil {
		return Sample{}, e
	}
	return s, nil
}
