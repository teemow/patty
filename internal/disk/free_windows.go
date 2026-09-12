//go:build windows

package disk

import "golang.org/x/sys/windows"

// Free returns the bytes available to the caller on the volume holding path.
func Free(path string) (int64, error) {
	var free, total, totalFree uint64
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return int64(free), nil
}
