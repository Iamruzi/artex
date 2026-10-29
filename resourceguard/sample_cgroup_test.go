package resourceguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxCPUAndMemoryParsing(t *testing.T) {
	total, idle, e := parseCPU("cpu  100 10 40 500 20 5 3 2 80 9\ncpu0 1")
	if e != nil || total != 680 || idle != 520 {
		t.Fatalf("CPU guest double count: %d/%d %v", total, idle, e)
	}
	total, available, e := parseMemory("MemTotal: 1024 kB\nMemFree: 50 kB\nMemAvailable: 512 kB\n")
	if e != nil || total != 1<<20 || available != 512<<10 {
		t.Fatalf("cache counted as exhausted: %d/%d %v", total, available, e)
	}
}

func TestAncestorCgroupLimitsAndTraversal(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "parent", "child")
	if e := os.MkdirAll(child, 0700); e != nil {
		t.Fatal(e)
	}
	write := func(dir, file, value string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, file), []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(child, "memory.max", "max")
	write(filepath.Dir(child), "memory.max", "1073741824")
	write(filepath.Dir(child), "memory.current", "805306368")
	write(root, "cpu.max", "150000 100000")
	write(root, "pids.max", "128")
	s := healthy()
	applyCgroups(&s, root, "0::/parent/child\n")
	if s.MemoryTotal != 1<<30 || s.MemoryAvailable != 256<<20 || s.CgroupMemoryMax != 1<<30 || s.CgroupPIDsMax != "128" || s.CgroupCPUQuota != "150000 100000" {
		t.Fatalf("lost parent limits %+v", s)
	}
	s = healthy()
	applyCgroups(&s, root, "0::/../../outside\n")
	if s.CgroupPIDsMax != "128" {
		t.Fatal("did not retain mount-root limits")
	}
}
