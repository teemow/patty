// Package localcreds finds the credentials configured on this machine, so a
// report can say that a leaked token is not just out there but still in use
// right here.
//
// Each provider says where its tools keep tokens: environment variables
// holding a token or naming a file, files under the config and home
// directories, commands that print one. The working directory's .env files
// are checked for every provider. Only fingerprints leave this package;
// token values are hashed as soon as they are read.
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
	for _, c := range candidateFiles(sources) {
		if content, err := os.ReadFile(c.path); err == nil {
			add(content, c.source)
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

// candidate is a file that may hold credentials, and how to name it in the
// report.
type candidate struct {
	path, source string
}

// candidateFiles lists every file the providers point at, each once. A file
// named by an environment variable comes first, so that its source says
// which variable led there when a provider also lists the path itself; a
// variable may list several files the way KUBECONFIG does.
func candidateFiles(sources []detect.LocalSources) []candidate {
	var cands []candidate
	config, home := configDir(), homeDir()
	for _, s := range sources {
		for _, name := range s.EnvFiles {
			for _, path := range filepath.SplitList(os.Getenv(name)) {
				if path != "" {
					cands = append(cands, candidate{path, display(path) + " ($" + name + ")"})
				}
			}
		}
	}
	for _, s := range sources {
		if config != "" {
			for _, f := range s.ConfigFiles {
				cands = append(cands, candidate{path: filepath.Join(config, f)})
			}
		}
		if home != "" {
			for _, f := range s.HomeFiles {
				cands = append(cands, candidate{path: filepath.Join(home, f)})
			}
		}
	}
	for _, pattern := range cwdFiles {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if abs, err := filepath.Abs(m); err == nil {
					cands = append(cands, candidate{path: abs})
				}
			}
		}
	}
	seen := map[string]bool{}
	uniq := cands[:0]
	for _, c := range cands {
		c.path = filepath.Clean(c.path)
		if seen[c.path] {
			continue
		}
		seen[c.path] = true
		if c.source == "" {
			c.source = display(c.path)
		}
		uniq = append(uniq, c)
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
