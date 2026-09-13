// Package providers assembles the credential providers patty ships with.
package providers

import (
	"os"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/anthropic"
	"github.com/teemow/patty/internal/detect/aws"
	"github.com/teemow/patty/internal/detect/azure"
	"github.com/teemow/patty/internal/detect/gcp"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/kubernetes"
	"github.com/teemow/patty/internal/detect/oci"
	"github.com/teemow/patty/internal/detect/openai"
	"github.com/teemow/patty/internal/detect/privatekey"
	"github.com/teemow/patty/internal/detect/slack"
	"github.com/teemow/patty/internal/detect/sops"
)

// Default returns the registry patty runs with: every provider against its
// public API, configured from the process environment.
func Default() *detect.Registry {
	return New(os.Getenv)
}

// New returns a registry of every provider against its public API, in
// report order, configured from env (ANTHROPIC_ADMIN_KEY, OPENAI_ADMIN_KEY).
// The container registry provider comes last and knows the others, so a
// registry password that is one of their credentials is reported as theirs.
func New(env func(string) string) *detect.Registry {
	peers := []detect.Provider{github.New(), slack.New(), aws.New(), gcp.New(), azure.New(), sops.New(), anthropic.New(), openai.New(), kubernetes.New(), privatekey.New()}
	return detect.NewRegistry(detect.Configure(env, append(peers, oci.New(peers...))...)...)
}
