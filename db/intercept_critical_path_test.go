package db

import (
	"encoding/json"
	"regexp"
	"testing"
)

func TestCriticalDirectoryDeletionKeepsDangerousPathsAndAvoidsReadOnlyFalseMatches(t *testing.T) {
	r := regexp.MustCompile(criticalDirectoryDeletePattern)
	for _, command := range []string{"rm /", "rm -f /etc/passwd", "rm /proc/1/status", "rm /usr/bin/tool", "rm /root/.ssh/key"} {
		raw, _ := json.Marshal(map[string]string{"command": command})
		if !r.Match(raw) {
			t.Errorf("dangerous path missed: %s", command)
		}
	}
	for _, command := range []string{"rm /tmp/task-owned-file", "rm /rooted/task-owned-file", "cat /proc/1/status", "rm local.tmp; cat /proc/1/status", "for d in /proc/[0-9]*; do cat $d/cmdline; done"} {
		raw, _ := json.Marshal(map[string]string{"command": command})
		if r.Match(raw) {
			t.Errorf("false critical path match: %s", command)
		}
	}
}

func TestCriticalDirectoryMigrationUpdatesLegacySeedAndPreservesCustomPattern(t *testing.T) {
	d := notifyTestDB(t)
	const name = "[内置] 删除系统关键目录"
	var original string
	var builtin bool
	if err := d.QueryRow(`SELECT pattern,builtin FROM intercept_rules WHERE name=$1`, name).Scan(&original, &builtin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`UPDATE intercept_rules SET pattern=$1,builtin=$2 WHERE name=$3`, original, builtin, name)
	})
	if _, err := d.Exec(`UPDATE intercept_rules SET pattern=$1,builtin=false WHERE name=$2`, historicalCriticalDirectoryPattern, name); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateCriticalDirectoryRule(); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := d.QueryRow(`SELECT pattern FROM intercept_rules WHERE name=$1`, name).Scan(&got); err != nil || got != criticalDirectoryDeletePattern {
		t.Fatalf("legacy seed was not updated: %v", err)
	}
	const custom = "custom-preserved-pattern"
	if _, err := d.Exec(`UPDATE intercept_rules SET pattern=$1 WHERE name=$2`, custom, name); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateCriticalDirectoryRule(); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT pattern FROM intercept_rules WHERE name=$1`, name).Scan(&got); err != nil || got != custom {
		t.Fatal("custom pattern overwritten")
	}
}
