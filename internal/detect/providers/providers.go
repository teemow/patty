// Package providers assembles the credential providers patty ships with.
package providers

import (
	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/aws"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/slack"
	"github.com/teemow/patty/internal/detect/sops"
)

// Default returns a registry of every provider against its public API, in
// report order.
func Default() *detect.Registry {
	return detect.NewRegistry(github.New(), slack.New(), aws.New(), sops.New())
}
