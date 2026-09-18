//go:build unix

package store

import "syscall"

func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	// Bavail, not Bfree: blocks reserved for root are not the relay's to use.
	return int64(st.Bavail) * int64(st.Bsize), nil
}
