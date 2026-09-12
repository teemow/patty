package disk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Cache is the directory patty mirrors repositories into. Mirrors live at
// <Dir>/<host>/<owner>/<repo>.git.
type Cache struct {
	Dir string
	// MaxBytes caps the total size of all mirrors in the cache.
	MaxBytes int64
	// MinFree is the free space that must remain on the drive after a clone.
	MinFree int64

	mu   sync.Mutex
	held map[string]bool
}

// Entry is one mirror in the cache.
type Entry struct {
	Path    string
	Size    int64
	ModTime time.Time
}

// ErrBudget is returned when a repository does not fit the disk budget.
var ErrBudget = errors.New("disk budget")

// RepoPath returns where the mirror of a repository lives.
func (c *Cache) RepoPath(host, owner, name string) string {
	return filepath.Join(c.Dir, host, owner, name+".git")
}

// Entries lists the mirrors in the cache, least recently used first.
func (c *Cache) Entries() ([]Entry, error) {
	matches, err := filepath.Glob(filepath.Join(c.Dir, "*", "*", "*.git"))
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || !info.IsDir() {
			continue
		}
		entries = append(entries, Entry{Path: m, Size: dirSize(m), ModTime: info.ModTime()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ModTime.Before(entries[j].ModTime) })
	return entries, nil
}

// Usage returns the total size of the cache.
func (c *Cache) Usage() int64 {
	return dirSize(c.Dir)
}

// Admit makes room for a repository of the estimated size and marks its
// path as in use so concurrent evictions leave it alone. It evicts the
// least recently used mirrors first and fails with ErrBudget when the
// repository still would not fit the budget or would push the drive below
// MinFree. Call Release when done with the path.
func (c *Cache) Admit(path string, estimate int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held == nil {
		c.held = make(map[string]bool)
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}

	if estimate > c.MaxBytes {
		return fmt.Errorf("%w: estimated %s exceeds --max-disk %s", ErrBudget, FormatSize(estimate), FormatSize(c.MaxBytes))
	}
	entries, err := c.Entries()
	if err != nil {
		return err
	}
	usage := int64(0)
	for _, e := range entries {
		usage += e.Size
	}
	for _, e := range entries {
		if usage+estimate <= c.MaxBytes {
			break
		}
		if c.held[e.Path] || e.Path == path {
			continue
		}
		if err := os.RemoveAll(e.Path); err != nil {
			return fmt.Errorf("evicting %s: %w", e.Path, err)
		}
		usage -= e.Size
	}
	if usage+estimate > c.MaxBytes {
		return fmt.Errorf("%w: cache holds %s, adding %s would exceed --max-disk %s", ErrBudget, FormatSize(usage), FormatSize(estimate), FormatSize(c.MaxBytes))
	}

	free, err := Free(c.Dir)
	if err != nil {
		return fmt.Errorf("checking free space: %w", err)
	}
	if free-estimate < c.MinFree {
		return fmt.Errorf("%w: %s free, cloning %s would leave less than --min-free %s", ErrBudget, FormatSize(free), FormatSize(estimate), FormatSize(c.MinFree))
	}
	c.held[path] = true
	return nil
}

// Release marks a path as no longer in use.
func (c *Cache) Release(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.held, path)
}

// Touch records use of a mirror so it is evicted last.
func Touch(path string) {
	now := time.Now()
	_ = os.Chtimes(path, now, now)
}

// Clean removes every mirror from the cache.
func (c *Cache) Clean() (int, int64, error) {
	entries, err := c.Entries()
	if err != nil {
		return 0, 0, err
	}
	var freed int64
	for _, e := range entries {
		if err := os.RemoveAll(e.Path); err != nil {
			return 0, freed, err
		}
		freed += e.Size
	}
	return len(entries), freed, nil
}

func dirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
