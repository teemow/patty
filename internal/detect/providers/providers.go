// Package providers assembles the credential providers patty ships with.
package providers

import (
	"os"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/anthropic"
	"github.com/teemow/patty/internal/detect/aws"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/openai"
	"github.com/teemow/patty/internal/detect/slack"
	"github.com/teemow/patty/internal/detect/sops"
)

// Default returns a registry of every provider against its public API, in
// report order, configured from the environment (ANTHROPIC_ADMIN_KEY,
// OPENAI_ADMIN_KEY).
func Default() *detect.Registry {
	return detect.NewRegistry(detect.Configure(os.Getenv,
		github.New(), slack.New(), aws.New(), sops.New(), anthropic.New(), openai.New())...)
}
