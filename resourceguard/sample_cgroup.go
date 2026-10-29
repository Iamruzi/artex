package resourceguard

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func parseCPU(body string) (total, idle uint64, err error) {
	f := strings.Fields(strings.SplitN(body, "\n", 2)[0])
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, fmt.Errorf("无效 /proc/stat")
	}
	// guest/guest_nice are already counted in user/nice.
	for i := 1; i < len(f) && i <= 8; i++ {
		n, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil {
			return 0, 0, e
		}
		total += n
		if i == 4 || i == 5 {
			idle += n
		}
	}
	return
}

func parseMemory(body string) (total, available uint64, err error) {
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] != "MemTotal:" && f[0] != "MemAvailable:" {
			continue
		}
		n, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil {
			return 0, 0, e
		}
		if f[0] == "MemTotal:" {
			total = n * 1024
		} else {
			available = n * 1024
		}
	}
	if total == 0 || available > total {
		return 0, 0, fmt.Errorf("无效 /proc/meminfo")
	}
	return
}

func applyCgroups(s *Sample, root, body string) {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		rel := strings.TrimPrefix(line, "0::")
		// A namespace may expose a parent path such as /../../slice. Do not read
		// outside the mount; the mount root remains an applicable ancestor.
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+rel), "/")))
		for {
			max, err := readUint(filepath.Join(dir, "memory.max"))
			used, e := readUint(filepath.Join(dir, "memory.current"))
			if err == nil && e == nil && max > 0 {
				free := uint64(0)
				if used < max {
					free = max - used
				}
				if s.CgroupMemoryMax == 0 || max < s.CgroupMemoryMax {
					s.CgroupMemoryMax = max
				}
				if max < s.MemoryTotal {
					s.MemoryTotal = max
				}
				if free < s.MemoryAvailable {
					s.MemoryAvailable = free
				}
			}
			if b, e := os.ReadFile(filepath.Join(dir, "cpu.max")); e == nil {
				v := strings.TrimSpace(string(b))
				if !strings.HasPrefix(v, "max") && (s.CgroupCPUQuota == "" || quota(v) < quota(s.CgroupCPUQuota)) {
					s.CgroupCPUQuota = v
				}
			}
			if b, e := os.ReadFile(filepath.Join(dir, "pids.max")); e == nil {
				v := strings.TrimSpace(string(b))
				n, e := strconv.ParseUint(v, 10, 64)
				old, _ := strconv.ParseUint(s.CgroupPIDsMax, 10, 64)
				if e == nil && (old == 0 || n < old) {
					s.CgroupPIDsMax = v
				}
			}
			if dir == root {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir || !strings.HasPrefix(parent+string(filepath.Separator), root+string(filepath.Separator)) {
				break
			}
			dir = parent
		}
	}
	if s.MemoryAvailable > s.MemoryTotal {
		s.MemoryAvailable = s.MemoryTotal
	}
}

func quota(v string) float64 {
	f := strings.Fields(v)
	if len(f) != 2 {
		return 1e20
	}
	n, e := strconv.ParseFloat(f[0], 64)
	d, e2 := strconv.ParseFloat(f[1], 64)
	if e != nil || e2 != nil || d <= 0 {
		return 1e20
	}
	return n / d
}
func readUint(path string) (uint64, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return 0, e
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}
