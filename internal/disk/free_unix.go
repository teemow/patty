//go:build !windows

package disk

import "golang.org/x/sys/unix"

// Free returns the bytes available to an unprivileged user on the
// filesystem holding path.
func Free(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil //nolint:unconvert // Bavail/Bsize types differ per platform
}
