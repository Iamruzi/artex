package db

// Root '/' requires a token boundary. The historical first alternative matched
// every absolute path, including /tmp/task-owned-file. Do not cross commands.
const criticalDirectoryDeletePattern = `\brm\b[^"'\n;|&]{0,60}["'\s](?:/(?:etc|bin|usr|boot|var|lib|sys|proc|dev|sbin|root)(?:/|["'\s;|&\\}]|$)|/(?:["'\s;|&\\}]|$))`
const historicalCriticalDirectoryPattern = `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`

func (d *DB) migrateCriticalDirectoryRule() error {
	// The original seed predates the builtin flag and still has builtin=false.
	// Match its full shipped signature instead of assuming that flag was migrated.
	_, err := d.Exec(`UPDATE intercept_rules SET pattern=$1,updated_at=now() WHERE name='[内置] 删除系统关键目录' AND pattern=$2 AND match_target='tool_input' AND match_type='regex' AND action='deny'`, criticalDirectoryDeletePattern, historicalCriticalDirectoryPattern)
	return err
}
