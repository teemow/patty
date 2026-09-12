// Package localcreds finds the credentials configured on this machine, so a
// report can say that a leaked token is not just out there but still in use
// right here.
//
// Each provider says where its tools keep tokens; the working directory's
// .env files are checked for every provider. Only fingerprints leave this
// package; token values are hashed as soon as they are read.
package localcreds

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Credential is one token configured locally, identified by fingerprint.
type Credential struct {
	Fingerprint string
	// Source says where it was found: a file path, an environment variable
	// or a command.
	Source string
}

// cwdFiles are the files in the working directory that hold credentials of
// any provider. Globs are allowed.
var cwdFiles = []string{".env", ".env.*", ".envrc", ".npmrc"}

// Find returns every credential configured on this machine that the
// registry's providers know where to look for. Missing files and failing
// commands are simply not credentials; Find never returns an error.
func Find(ctx context.Context, registry *detect.Registry) []Credential {
	seen := map[string]bool{}
	var out []Credential
	add := func(content []byte, source string) {
		for _, tok := range registry.Find(content) {
			fp := tok.Fingerprint()
			if !seen[fp+source] {
				seen[fp+source] = true
				out = append(out, Credential{Fingerprint: fp, Source: source})
			}
		}
	}
	var sources []detect.LocalSources
	for _, p := range registry.Providers() {
		sources = append(sources, p.LocalSources())
	}
	for _, s := range sources {
		for _, name := range s.Env {
			if v := os.Getenv(name); v != "" {
				add([]byte(v), "$"+name)
			}
		}
	}
	for _, path := range candidateFiles(sources) {
		if content, err := os.ReadFile(path); err == nil {
			add(content, display(path))
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, s := range sources {
		for _, argv := range s.Commands {
			if out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output(); err == nil {
				add(out, strings.Join(argv, " "))
			}
		}
	}
	return out
}

// Match indexes credentials by fingerprint: the sources each token is
// configured in.
func Match(creds []Credential) map[string][]string {
	m := map[string][]string{}
	for _, c := range creds {
		m[c.Fingerprint] = append(m[c.Fingerprint], c.Source)
	}
	return m
}

func candidateFiles(sources []detect.LocalSources) []string {
	var paths []string
	config, home := configDir(), homeDir()
	for _, s := range sources {
		if config != "" {
			for _, f := range s.ConfigFiles {
				paths = append(paths, filepath.Join(config, f))
			}
		}
		if home != "" {
			for _, f := range s.HomeFiles {
				paths = append(paths, filepath.Join(home, f))
			}
		}
	}
	for _, pattern := range cwdFiles {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if abs, err := filepath.Abs(m); err == nil {
					paths = append(paths, abs)
				}
			}
		}
	}
	seen := map[string]bool{}
	uniq := paths[:0]
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	return uniq
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// configDir follows the XDG convention gh, hub and Copilot use on every
// platform, rather than os.UserConfigDir which points elsewhere on macOS.
func configDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	if home := homeDir(); home != "" {
		return filepath.Join(home, ".config")
	}
	return ""
}

// display shortens a path under the home directory to ~/....
func display(path string) string {
	if home := homeDir(); home != "" {
		if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return path
}
