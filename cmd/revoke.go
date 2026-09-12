package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/report"
	"github.com/teemow/patty/internal/scan"
)

func init() {
	var yes bool
	revokeCmd := &cobra.Command{
		Use:   "revoke [token...]",
		Short: "Ask GitHub to revoke tokens you have in hand",
		Long: `Revoke submits tokens to GitHub's credential revocation endpoint. It needs
no authentication -- it is meant for whoever finds a leaked token -- and
GitHub notifies the owner of every revocation.

Tokens are read from the arguments, or from standard input when there are
none, so a value never has to touch the shell history:

  patty revoke < leaked.txt
  patty . --show-secrets --json | jq -r '.results[].findings[].token' | patty revoke

Anything that is not a well-formed GitHub token is ignored. Personal access
tokens (classic and fine-grained), OAuth tokens, user-to-server and refresh
tokens can be revoked; installation tokens (ghs_) cannot.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.yes = yes
			return runRevoke(cmd, args)
		},
	}
	revokeCmd.Flags().BoolVarP(&yes, "yes", "y", false, "Revoke without asking for confirmation")
	rootCmd.AddCommand(revokeCmd)
}

func runRevoke(cmd *cobra.Command, args []string) error {
	input := strings.Join(args, "\n")
	if len(args) == 0 {
		raw, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return err
		}
		input = string(raw)
	}
	tokens := parseTokens(input)
	if len(tokens) == 0 {
		return errors.New("no GitHub tokens in the input")
	}
	var findings []scan.Finding
	for _, tok := range tokens {
		if !detect.Revocable(tok.Kind) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "skipping %s (%s): %s tokens cannot be revoked through the API\n", detect.Redact(tok.Value), tok.Fingerprint(), tok.Kind)
			continue
		}
		findings = append(findings, scan.Finding{Kind: tok.Kind, Fingerprint: tok.Fingerprint(), Token: tok.Value, Redacted: detect.Redact(tok.Value), ChecksumVerified: tok.ChecksumVerified})
	}
	if len(findings) == 0 {
		return errors.New("nothing to revoke")
	}
	results := []scan.Result{{Target: "input", Findings: findings}}
	if err := revoke(cmd, results, findings, detect.NewVerifier()); err != nil {
		return err
	}
	for _, f := range results[0].Findings {
		state := "revoked"
		if f.Revocation == scan.RevocationPending {
			state = "pending: GitHub is still processing it"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %-24s fp %s  %s\n", f.Redacted, f.Kind, f.Fingerprint, state)
	}
	return nil
}

// parseTokens extracts distinct well-formed tokens from free text.
func parseTokens(input string) []detect.Token {
	var out []detect.Token
	seen := map[string]bool{}
	for _, tok := range detect.Find([]byte(input)) {
		if !seen[tok.Value] {
			seen[tok.Value] = true
			out = append(out, tok)
		}
	}
	return out
}

// revokeActive revokes every active token in results after confirmation.
func revokeActive(cmd *cobra.Command, results []scan.Result, verifier *detect.Verifier) error {
	tokens := scan.Revocable(results)
	if len(tokens) == 0 {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "No active tokens to revoke")
		return nil
	}
	return revoke(cmd, results, tokens, verifier)
}

func revoke(cmd *cobra.Command, results []scan.Result, tokens []scan.Finding, verifier *detect.Verifier) error {
	stderr := cmd.ErrOrStderr()
	_, _ = fmt.Fprintf(stderr, "\nAbout to ask GitHub to revoke %d %s; the owner of each will be notified:\n", len(tokens), report.Plural(len(tokens), "token", "tokens"))
	for _, f := range tokens {
		line := fmt.Sprintf("  %s  %-24s fp %s", f.Redacted, f.Kind, f.Fingerprint)
		if f.Verification != nil && f.Verification.Detail != "" {
			line += "  " + f.Verification.Detail
		}
		_, _ = fmt.Fprintln(stderr, line)
		for _, w := range warnings(f) {
			_, _ = fmt.Fprintln(stderr, "      "+w)
		}
	}
	ok, err := confirm(cmd, "Proceed? [y/N] ")
	if err != nil {
		return err
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "Not revoking anything")
		return nil
	}
	done, err := scan.Revoke(cmd.Context(), results, tokens, detect.NewRevoker(), verifier)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("GitHub accepted the revocation of %d %s", len(tokens), report.Plural(len(tokens), "token", "tokens"))
	if done < len(tokens) {
		msg += fmt.Sprintf("; %d still answered as active and should go quiet shortly", len(tokens)-done)
	}
	_, _ = fmt.Fprintln(stderr, msg)
	return nil
}

// warnings names the side effects of revoking this token that are easy to
// miss: an OAuth revocation takes the application's whole authorization with
// it, and a token still configured locally logs that tool out.
func warnings(f scan.Finding) []string {
	var out []string
	switch f.Kind {
	case detect.KindOAuth, detect.KindUserToServer, detect.KindRefresh:
		app := "this application"
		if f.Verification != nil && f.Verification.Issuer() != "" {
			app = f.Verification.Issuer()
		}
		out = append(out, fmt.Sprintf("warning: revokes the whole authorization of %s, every token it holds for this user, including current logins", app))
	}
	if len(f.Local) > 0 {
		out = append(out, "warning: still configured in "+strings.Join(f.Local, ", ")+"; that tool stops working until it gets a new token")
	}
	return out
}

// confirm asks on the terminal unless --yes was given. Without a terminal
// and without --yes it refuses, so a script cannot revoke by accident.
func confirm(cmd *cobra.Command, prompt string) (bool, error) {
	if opts.yes {
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
