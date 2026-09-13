package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// fileHit is one place a token was found in a file tree.
type fileHit struct {
	path string
	line int
}

// Dir scans every regular file below root as it is on disk, whether or not
// the tree is a repository, so the files a repository scan never sees are
// covered: an untracked .env, a credentials file copied into a project
// folder. A single file as root is scanned on its own. Symbolic links are
// not followed; .git directories, devices, sockets and pipes are left out;
// files larger than opts.MaxObject are skipped and counted. .gitignore is
// deliberately not honoured, since ignored files are where credentials
// hide. A finding's path is relative to root and it has no commit.
func Dir(ctx context.Context, name, root string, opts Options) (Result, error) {
	start := time.Now()
	res := Result{Target: name, Files: true}
	base, paths, unreadable, err := walk(root, opts.MaxObject, &res.Stats)
	if err != nil {
		return res, err
	}

	c := newCollector[fileHit](opts)
	err = parallel(ctx, paths, opts.workers(), func(shard []string) error {
		var local int64
		for _, p := range shard {
			if err := ctx.Err(); err != nil {
				return err
			}
			content, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(p)))
			if err != nil {
				c.mu.Lock()
				unreadable++
				c.mu.Unlock()
				continue
			}
			local += int64(len(content))
			c.observe(p, content)
			c.find(content, func(line int) fileHit { return fileHit{p, line} })
		}
		c.read(local)
		return nil
	})
	if err != nil {
		return res, err
	}
	res.Stats.Scanned = len(paths) - unreadable
	res.Stats.Bytes = c.bytes
	if unreadable > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d files could not be read", unreadable))
	}

	if len(c.findings) > 0 {
		filePaths := map[string]string{}
		for p := range c.sightings {
			filePaths[p] = p
		}
		for value, locs := range c.hits {
			f := c.findings[value]
			for h := range locs {
				f.Locations = append(f.Locations, Location{Repo: name, Path: h.path, Line: h.line, ObjectType: "file"})
			}
			sortLocations(f.Locations)
		}
		correlate(ctx, name, c.registry, c.findings, c.sightings, filePaths, nil)
		c.bind(func(h fileHit) string { return h.path })
	}
	res.Findings = c.results(ctx, opts)
	res.Stats.Duration = time.Since(start)
	return res, nil
}

// walk lists the regular files below root as slash-separated paths relative
// to base, the directory they are read from: root itself, or the parent of
// a root that is a single file. Every regular file counts as an object;
// one larger than maxSize is skipped and counted as such. Entries that
// cannot be read are counted as unreadable and left out.
func walk(root string, maxSize int64, stats *Stats) (base string, paths []string, unreadable int, err error) {
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, 0, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", nil, 0, err
	}
	admit := func(rel string, size int64) {
		stats.Objects++
		if maxSize > 0 && size > maxSize {
			stats.Skipped++
			return
		}
		paths = append(paths, rel)
	}
	if !info.IsDir() {
		admit(filepath.Base(root), info.Size())
		return filepath.Dir(root), paths, 0, nil
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			unreadable++
			return nil
		}
		if d.Name() == ".git" && p != root {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil // the gitdir pointer file of a worktree or submodule
		}
		if !d.Type().IsRegular() {
			return nil // directories are descended into; links, devices, sockets and pipes are not files
		}
		info, err := d.Info()
		if err != nil {
			unreadable++
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		admit(filepath.ToSlash(rel), info.Size())
		return nil
	})
	return root, paths, unreadable, err
}
