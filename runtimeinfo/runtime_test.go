package runtimeinfo

import (
	"errors"
	"testing"
)

func TestPythonAbsenceDoesNotProbeOrRequireInstallation(t *testing.T) {
	calls := 0
	got := detectPython("", func(string) (string, error) { return "", errors.New("missing") }, func(string) (string, error) { calls++; return "", nil })
	if got.Available || calls != 0 {
		t.Fatal("missing runtime searched or probed")
	}
}
func TestPythonVerifiedPathAndStoreShim(t *testing.T) {
	got := detectPython("", func(name string) (string, error) {
		if name == "python3" {
			return `C:\Users\x\Microsoft\WindowsApps\python3.exe`, nil
		}
		return `C:\Python314\python.exe`, nil
	}, func(path string) (string, error) {
		if path != `C:\Python314\python.exe` {
			t.Fatal("Store shim executed")
		}
		return "Python 3.14.0\n", nil
	})
	if !got.Available || got.Version != "Python 3.14.0" {
		t.Fatalf("%+v", got)
	}
}
func TestExplicitInvalidPythonDoesNotSilentlySearch(t *testing.T) {
	got := detectPython("/configured/python", func(string) (string, error) { t.Fatal("explicit runtime silently replaced"); return "", nil }, func(string) (string, error) { return "Python 2.7.18", nil })
	if got.Available {
		t.Fatal("Python 2 accepted")
	}
}
