package disk

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAndFormatSize(t *testing.T) {
	cases := map[string]int64{
		"0": 0, "1024": 1024, "1K": KiB, "512M": 512 * MiB, "10G": 10 * GiB, "1.5T": TiB + TiB/2,
		"2 GiB": 2 * GiB, "3gb": 3 * GiB, "7MB": 7 * MiB,
	}
	for in, want := range cases {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "G", "-1G", "1X", "abc"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) must fail", bad)
		}
	}
	if FormatSize(1536*MiB) != "1.5 GiB" || FormatSize(512) != "512 B" || FormatSize(2*KiB) != "2.0 KiB" {
		t.Fatalf("FormatSize wrong: %s %s %s", FormatSize(1536*MiB), FormatSize(512), FormatSize(2*KiB))
	}
}

func mirror(t *testing.T, c *Cache, owner, name string, size int, age time.Duration) string {
	t.Helper()
	p := c.RepoPath("github.com", owner, name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "pack"), make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdmitEvictsLRUAndRespectsBudget(t *testing.T) {
	c := &Cache{Dir: t.TempDir(), MaxBytes: 1000, MinFree: 0}
	old := mirror(t, c, "a", "old", 400, 2*time.Hour)
	recent := mirror(t, c, "a", "recent", 400, time.Minute)

	entries, err := c.Entries()
	if err != nil || len(entries) != 2 || entries[0].Path != old {
		t.Fatalf("entries must be LRU first: %+v %v", entries, err)
	}
	if c.Usage() != 800 {
		t.Fatalf("usage = %d", c.Usage())
	}

	target := c.RepoPath("github.com", "b", "new")
	if err := c.Admit(target, 300); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("least recently used mirror must be evicted")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("recent mirror must survive")
	}

	// The admitted path is held: it cannot be evicted for the next one, and
	// 400 (recent) + 300 (held, not yet on disk) leaves room for 300 only.
	if err := c.Admit(c.RepoPath("github.com", "b", "huge"), 2000); !errors.Is(err, ErrBudget) {
		t.Fatalf("oversized repo must be refused: %v", err)
	}
	mirror(t, c, "b", "new", 300, 0)
	if err := c.Admit(c.RepoPath("github.com", "c", "x"), 700); err != nil {
		t.Fatalf("evicting the unheld recent mirror must make room: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("held mirror must not be evicted")
	}
	c.Release(target)

	n, freed, err := c.Clean()
	if err != nil || n != 1 || freed != 300 {
		t.Fatalf("Clean = %d %d %v", n, freed, err)
	}
}

func TestAdmitKeepsMinFree(t *testing.T) {
	c := &Cache{Dir: t.TempDir(), MaxBytes: 1 << 50, MinFree: 1 << 50}
	if err := c.Admit(c.RepoPath("github.com", "a", "b"), 1); !errors.Is(err, ErrBudget) {
		t.Fatalf("must refuse when free space would drop below min-free: %v", err)
	}
	free, err := Free(c.Dir)
	if err != nil || free <= 0 {
		t.Fatalf("Free = %d, %v", free, err)
	}
}
