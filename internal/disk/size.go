// Package disk keeps patty's clone cache within a byte budget and off the
// last free gigabytes of the drive.
package disk

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	KiB int64 = 1 << 10
	MiB int64 = 1 << 20
	GiB int64 = 1 << 30
	TiB int64 = 1 << 40
)

var units = map[string]int64{
	"": 1, "B": 1,
	"K": KiB, "KB": KiB, "KIB": KiB,
	"M": MiB, "MB": MiB, "MIB": MiB,
	"G": GiB, "GB": GiB, "GIB": GiB,
	"T": TiB, "TB": TiB, "TIB": TiB,
}

// ParseSize parses a human size such as "10G", "512MiB", "1.5T" or a plain
// number of bytes.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := len(s)
	for i > 0 && (s[i-1] < '0' || s[i-1] > '9') && s[i-1] != '.' {
		i--
	}
	num, unit := s[:i], strings.ToUpper(strings.TrimSpace(s[i:]))
	mult, ok := units[unit]
	if !ok || num == "" {
		return 0, fmt.Errorf("invalid size %q (use e.g. 500M, 10G, 1.5T)", s)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(f * float64(mult)), nil
}

// FormatSize renders bytes with a binary unit and one decimal.
func FormatSize(n int64) string {
	switch {
	case n >= TiB:
		return fmt.Sprintf("%.1f TiB", float64(n)/float64(TiB))
	case n >= GiB:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(GiB))
	case n >= MiB:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(MiB))
	case n >= KiB:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(KiB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
