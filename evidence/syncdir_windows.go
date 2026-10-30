//go:build windows

package evidence

// Windows does not support File.Sync on a directory opened through os.Open.
// The body itself has already been flushed and closed before its rename. Do not
// convert a successful evidence write into AccessDenied by flushing a directory.
// Directory metadata durability across power failure is not guaranteed here.
func syncEvidenceDirectory(string) error { return nil }
