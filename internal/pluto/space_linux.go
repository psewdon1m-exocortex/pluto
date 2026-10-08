package pluto

import (
	"errors"
	"syscall"
)

func checkSpoolSpace(directory string, size int64) error {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(directory, &stats); err != nil {
		return err
	}
	if uint64(size+16*1024*1024) > stats.Bavail*uint64(stats.Bsize) {
		return errors.New("insufficient free space for a verified file snapshot")
	}
	return nil
}
