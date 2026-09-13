package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/providers"
)

// The kinds subcommand prints what every provider's Kinds reports as a
// markdown table. It is hidden: `make docs` pastes the table into
// docs/how-it-works.md, and CI fails when the two drift apart.
func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:    "kinds",
		Short:  "Print the registered credential kinds as a markdown table",
		Hidden: true,
		Args:   cobra.NoArgs,
		Run:    func(cmd *cobra.Command, _ []string) { writeKinds(cmd.OutOrStdout()) },
	})
}

// writeKinds renders the table from a registry built without operator
// configuration, so the output is the same on every machine. A kind that
// becomes revocable once the operator configures the provider is marked
// with the environment variables that do it.
func writeKinds(w io.Writer) {
	_, _ = fmt.Fprintln(w, "| Provider | Kind | Description | Revocable via API |")
	_, _ = fmt.Fprintln(w, "|----------|------|-------------|-------------------|")
	unset := func(string) string { return "" }
	for _, p := range providers.New(unset).Providers() {
		kinds := p.Kinds()
		configured, vars := configuredKinds(p)
		for i, k := range kinds {
			_, _ = fmt.Fprintf(w, "| %s | `%s` | %s | %s |\n", p.Name(), k.Kind, cell(k.Description), revocable(p, k, configured[i], vars))
		}
	}
}

// revocable is the table's last column: whether --revoke handles the kind
// as the Registry decides it, marked revocable by a provider that is a
// Revoker; "with VAR" when only operator configuration makes it so.
func revocable(p detect.Provider, k, configured detect.KindInfo, vars []string) string {
	if _, ok := p.(detect.Revoker); !ok {
		return "no"
	}
	switch {
	case k.Revocable:
		return "yes"
	case configured.Revocable:
		return "with " + strings.Join(vars, ", ")
	}
	return "no"
}

// configuredKinds returns what p reports once every environment variable
// it reads is set, and the names of those variables. For a provider that
// takes no configuration it is p.Kinds() and nil.
func configuredKinds(p detect.Provider) ([]detect.KindInfo, []string) {
	c, ok := p.(detect.Configurable)
	if !ok {
		return p.Kinds(), nil
	}
	var vars []string
	c.Configure(func(name string) string {
		vars = append(vars, name)
		return "configured"
	})
	return p.Kinds(), vars
}

// cell escapes the one character a markdown table cell cannot hold.
func cell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}
