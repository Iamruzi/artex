// Package buildinfo identifies the Byte2Cat integration independently of the
// upstream application's semantic version and update signing authority.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

const Edition = "Byte2Cat"
const Version = "0.1.0"

type Info struct {
	Version  string `json:"version"`
	Edition  string `json:"edition"`
	Revision string `json:"revision"`
	Dirty    bool   `json:"dirty"`
	Display  string `json:"display_version"`
}

func New(version, revision string) Info {
	info := Info{Version: strings.TrimPrefix(version, "v"), Edition: Edition, Revision: revision}
	if info.Version == "" {
		info.Version = Version
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" && info.Revision == "" {
				info.Revision = setting.Value
			}
			if setting.Key == "vcs.modified" {
				info.Dirty = setting.Value == "true"
			}
		}
	}
	return format(info)
}

func format(info Info) Info {
	hash := info.Revision
	if hash == "" {
		hash = "unknown"
	}
	if len(hash) > 12 {
		hash = hash[:12]
	}
	if info.Dirty {
		hash += "-dirty"
	}
	info.Display = info.Edition + " v" + info.Version + " · " + hash
	return info
}
