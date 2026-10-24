package server

// Experimental session-context compression. Kept separate from graph compaction
// and disabled by default; all agents read this at the start of each run.
const settingNoaCompaction = "noa_compaction"

func (m *Manager) NoaCompactionEnabled() bool {
	return m.pg.GetBool(settingNoaCompaction, false)
}

func (m *Manager) SetNoaCompaction(on bool) error {
	return m.pg.SetBool(settingNoaCompaction, on)
}
