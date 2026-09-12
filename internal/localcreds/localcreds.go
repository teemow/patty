// Package localcreds finds the GitHub tokens configured on this machine, so
// a report can say that a leaked token is not just out there but still in
// use right here.
//
// Only fingerprints leave this package; token values are hashed as soon as
// they are read.
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

// Env vars CLIs read tokens from.
var envVars = []string{"GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// Files under the config dir, the home dir and the working directory that
// tools store tokens in. Globs are allowed.
var (
	configFiles = []string{
		"gh/hosts.yml",
		"hub",
		"github-copilot/hosts.json",
		"github-copilot/apps.json",
		"git/credentials",
	}
	homeFiles = []string{
		".git-credentials",
		".netrc",
		".gitconfig",
		".config/gh/hosts.yml",
	}
	cwdFiles = []string{".env", ".env.*", ".envrc", ".npmrc"}
)

// Find returns every GitHub token configured on this machine that patty
// knows where to look for. Missing files and failing commands are simply
// not credentials; Find never returns an error.
func Find(ctx context.Context) []Credential {
	seen := map[string]bool{}
	var out []Credential
	add := func(content []byte, source string) {
		for _, tok := range detect.Find(content) {
			fp := tok.Fingerprint()
			if !seen[fp+source] {
				seen[fp+source] = true
				out = append(out, Credential{Fingerprint: fp, Source: source})
			}
		}
	}
	for _, name := range envVars {
		if v := os.Getenv(name); v != "" {
			add([]byte(v), "$"+name)
		}
	}
	for _, path := range candidateFiles() {
		if content, err := os.ReadFile(path); err == nil {
			add(content, display(path))
		}
	}
	// gh may keep its token in the system keyring rather than hosts.yml.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output(); err == nil {
		add(out, "gh auth token")
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

func candidateFiles() []string {
	var paths []string
	if dir := configDir(); dir != "" {
		for _, f := range configFiles {
			paths = append(paths, filepath.Join(dir, f))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, f := range homeFiles {
			paths = append(paths, filepath.Join(home, f))
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

// configDir follows the XDG convention gh, hub and Copilot use on every
// platform, rather than os.UserConfigDir which points elsewhere on macOS.
func configDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config")
	}
	return ""
}

// display shortens a path under the home directory to ~/....
func display(path string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return path
}
