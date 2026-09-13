package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/providers"
	"github.com/teemow/patty/internal/report"
	"github.com/teemow/patty/internal/scan"
)

func init() {
	rootCmd.AddCommand(newRevokeCmd())
}

// newRevokeCmd builds the revoke subcommand; its provider registry is built
// when it runs.
func newRevokeCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "revoke [token...]",
		Short: "Ask the provider to revoke tokens you have in hand",
		Long: `Revoke submits each token to its provider's revocation endpoint. GitHub
tokens go to the unauthenticated credential revocation endpoint -- it is
meant for whoever finds a leaked token -- and GitHub notifies the owner.
Slack tokens go to auth.revoke, authenticated with the token itself. An AWS
access key is deactivated through iam:UpdateAccessKey on its own user,
signed with the key itself, which only works when the input holds the key
id and its secret and the user may manage its own keys. Anthropic and
OpenAI keys are found in the organization's key list and deactivated or
deleted through its Admin API, which needs an admin key of that
organization in ANTHROPIC_ADMIN_KEY or OPENAI_ADMIN_KEY. A Docker Hub
personal access token logs in, finds itself in its account's token list
and sets itself inactive, which a read-only token may not.

Tokens are read from the arguments, or from standard input when there are
none, so a value never has to touch the shell history:

  patty revoke < leaked.txt
  patty . --show-secrets --json | jq -r '.results[].findings[].token' | patty revoke

Anything that is not a well-formed token is ignored, and so is a token of
a kind no API revokes: the report says where to revoke or how to rotate
those by hand, and the detection table in docs/how-it-works.md says for
every kind whether --revoke handles it.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd, args, revocation{registry: providers.Default(), yes: yes})
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Revoke without asking for confirmation")
	return cmd
}

// revocation is the interactive revocation flow shared by --revoke and the
// revoke subcommand: it lists what is about to happen, asks, and reports.
type revocation struct {
	registry *detect.Registry
	// yes skips the confirmation.
	yes bool
}

func runRevoke(cmd *cobra.Command, args []string, r revocation) error {
	input := strings.Join(args, "\n")
	if len(args) == 0 {
		raw, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return err
		}
		input = string(raw)
	}
	tokens := parseTokens(r.registry, input)
	if len(tokens) == 0 {
		return errors.New("no tokens in the input")
	}
	var findings []scan.Finding
	for _, tok := range tokens {
		if !r.registry.Revocable(tok.Kind) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "skipping %s (%s): %s credentials cannot be revoked through the API\n", detect.Redact(tok.Value), tok.Fingerprint(), tok.Kind)
			continue
		}
		findings = append(findings, *scan.NewFinding(r.registry, tok))
	}
	if len(findings) == 0 {
		return errors.New("nothing to revoke")
	}
	results := []scan.Result{{Target: "input", Findings: findings}}
	if err := r.revoke(cmd, results, findings); err != nil {
		return err
	}
	for _, f := range results[0].Findings {
		state := "revoked"
		if f.Revocation == scan.RevocationPending {
			state = "pending: " + f.Provider + " is still processing it"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %-24s fp %s  %s\n", f.Redacted, f.Kind, f.Fingerprint, state)
	}
	return nil
}

// parseTokens extracts distinct well-formed tokens from free text.
func parseTokens(registry *detect.Registry, input string) []detect.Token {
	var out []detect.Token
	seen := map[string]bool{}
	for _, tok := range registry.Find([]byte(input)) {
		if !seen[tok.Value] {
			seen[tok.Value] = true
			out = append(out, tok)
		}
	}
	return out
}

// active revokes every active credential in results after confirmation.
func (r revocation) active(cmd *cobra.Command, results []scan.Result) error {
	tokens := scan.Revocable(results, r.registry)
	if len(tokens) == 0 {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "No active credentials to revoke")
		return nil
	}
	return r.revoke(cmd, results, tokens)
}

func (r revocation) revoke(cmd *cobra.Command, results []scan.Result, tokens []scan.Finding) error {
	stderr := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(stderr, "\nAbout to ask %s to revoke %d %s:\n", providerNames(tokens), len(tokens), report.Plural(len(tokens), "credential", "credentials"))
	for _, f := range tokens {
		line := fmt.Sprintf("  %s  %-24s fp %s", f.Redacted, f.Kind, f.Fingerprint)
		if f.Verification != nil && f.Verification.Detail != "" {
			line += "  " + f.Verification.Detail
		}
		_, _ = fmt.Fprintln(stderr, line)
		for _, w := range r.warnings(f) {
			_, _ = fmt.Fprintln(stderr, "      "+w)
		}
		if note := r.rehearse(cmd, f); note != "" {
			_, _ = fmt.Fprintln(stderr, "      "+note)
		}
	}
	ok, err := r.confirm(cmd, "Proceed? [y/N] ")
	if err != nil {
		return err
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "Not revoking anything")
		return nil
	}
	done, err := scan.Revoke(cmd.Context(), results, tokens, r.registry)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("Revocation of %d %s accepted", len(tokens), report.Plural(len(tokens), "credential", "credentials"))
	if done < len(tokens) {
		msg += fmt.Sprintf("; %d still answered as active and should go quiet shortly", len(tokens)-done)
	}
	_, _ = fmt.Fprintln(stderr, msg)
	return nil
}

// providerNames lists the providers of the given credentials: "GitHub",
// "GitHub and Slack".
func providerNames(tokens []scan.Finding) string {
	seen := map[string]bool{}
	var names []string
	for _, f := range tokens {
		if !seen[f.Provider] {
			seen[f.Provider] = true
			names = append(names, f.Provider)
		}
	}
	sort.Strings(names)
	if len(names) > 1 {
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
	return strings.Join(names, "")
}

// rehearse asks a provider that supports it how the revocation would go,
// without revoking anything, so the answer is on the screen before the user
// confirms. Providers without a dry run contribute nothing.
func (r revocation) rehearse(cmd *cobra.Command, f scan.Finding) string {
	dr, ok := r.registry.Provider(f.Kind).(detect.DryRunRevoker)
	if !ok {
		return ""
	}
	if err := dr.DryRunRevoke(cmd.Context(), f.Detected()); err != nil {
		return "dry run: " + err.Error()
	}
	return "dry run: " + f.Provider + " would accept the revocation"
}

// warnings names the side effects of revoking this credential that are easy
// to miss: an OAuth revocation takes the application's whole authorization
// with it, and a token still configured locally logs that tool out.
func (r revocation) warnings(f scan.Finding) []string {
	var out []string
	if effect := r.registry.Info(f.Kind).RevokeEffect; effect != "" {
		app := "this application"
		if f.Verification != nil && f.Verification.Issuer() != "" {
			app = f.Verification.Issuer()
		}
		out = append(out, "warning: "+strings.ReplaceAll(effect, "{app}", app))
	}
	if len(f.Local) > 0 {
		out = append(out, "warning: still configured in "+strings.Join(f.Local, ", ")+"; that tool stops working until it gets a new token")
	}
	return out
}

// confirm asks on the terminal unless --yes was given. Without a terminal
// and without --yes it refuses, so a script cannot revoke by accident.
func (r revocation) confirm(cmd *cobra.Command, prompt string) (bool, error) {
	if r.yes {
		return true, nil
	}
	in, isFile := cmd.InOrStdin().(*os.File)
	if !isFile || !isTerminal(in) {
		return false, errors.New("refusing to revoke without confirmation: run interactively or pass --yes")
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), prompt)
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
