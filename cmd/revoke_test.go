package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/providers"
	"github.com/teemow/patty/internal/detect/slack"
	"github.com/teemow/patty/internal/scan"
)

func token(kind byte, random string) string {
	return "gh" + string(kind) + "_" + random + github.Checksum(random)
}

// slackBot builds a well-formed bot token at runtime.
func slackBot(secret string) string {
	return "xoxb-" + "1234567890" + "-" + "1234567890123" + "-" + secret
}

func TestParseTokens(t *testing.T) {
	pat := token('p', "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	app := token('s', "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	bot := slackBot(strings.Repeat("Ab", 12))
	input := "leaked: " + pat + "\n" + pat + "\nnot-a-token gh" + "p_short\n" + app + "\n" + bot + "\n"
	got := parseTokens(providers.Default(), input)
	if len(got) != 3 || got[0].Value != pat || got[1].Kind != github.KindServerToServer || got[2].Kind != slack.KindBot {
		t.Fatalf("parseTokens = %+v", got)
	}
}

func TestRevokeRefusesWithoutTerminalOrYes(t *testing.T) {
	cmd := &cobra.Command{}
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader("y\n"))
	r := revocation{registry: providers.Default()}
	if ok, err := r.confirm(cmd, "? "); ok || err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("confirm = %v, %v", ok, err)
	}
	r.yes = true
	if ok, err := r.confirm(cmd, "? "); !ok || err != nil {
		t.Fatalf("--yes must confirm: %v, %v", ok, err)
	}
	r.yes = false

	// The subcommand itself refuses installation tokens and empty input before touching the network.
	rc := newRevokeCmd()
	rc.SetIn(strings.NewReader("nothing here"))
	rc.SetErr(&stderr)
	if err := runRevoke(rc, nil, r); err == nil || err.Error() != "no tokens in the input" {
		t.Fatalf("empty: %v", err)
	}
	rc.SetIn(strings.NewReader(token('s', "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")))
	if err := runRevoke(rc, nil, r); err == nil || err.Error() != "nothing to revoke" || !strings.Contains(stderr.String(), "cannot be revoked through the API") {
		t.Fatalf("installation token: %v\n%s", err, stderr.String())
	}
	stderr.Reset()
	rc.SetIn(strings.NewReader("https://hooks.slack.com/" + "services/" + "T" + "0123ABCD" + "/" + "B" + "0123ABCDEF" + "/" + "AbCdEfGhIjKlMnOpQrStUvWx"))
	if err := runRevoke(rc, nil, r); err == nil || err.Error() != "nothing to revoke" || !strings.Contains(stderr.String(), "slack-webhook credentials cannot be revoked") {
		t.Fatalf("webhook: %v\n%s", err, stderr.String())
	}
}

func TestProviderNames(t *testing.T) {
	if got := providerNames([]scan.Finding{{Provider: "Slack"}, {Provider: "GitHub"}, {Provider: "Slack"}}); got != "GitHub and Slack" {
		t.Fatalf("providerNames = %q", got)
	}
	if got := providerNames([]scan.Finding{{Provider: "GitHub"}}); got != "GitHub" {
		t.Fatalf("providerNames = %q", got)
	}
}

func TestWarnings(t *testing.T) {
	r := revocation{registry: providers.Default()}
	cli := scan.Finding{Kind: github.KindOAuth, Verification: &detect.Verification{App: "GitHub CLI"}, Local: []string{"~/.config/gh/hosts.yml"}}
	got := r.warnings(cli)
	if len(got) != 2 || !strings.Contains(got[0], "whole authorization of GitHub CLI") || !strings.Contains(got[1], "~/.config/gh/hosts.yml") {
		t.Fatalf("warnings = %q", got)
	}
	if got := r.warnings(scan.Finding{Kind: github.KindPAT}); len(got) != 0 {
		t.Fatalf("plain PAT has no warnings: %q", got)
	}
	if got := r.warnings(scan.Finding{Kind: github.KindUserToServer}); len(got) != 1 || !strings.Contains(got[0], "this application") {
		t.Fatalf("unknown app: %q", got)
	}
	if got := r.warnings(scan.Finding{Kind: slack.KindBot}); len(got) != 1 || !strings.Contains(got[0], "reinstalled") {
		t.Fatalf("slack bot: %q", got)
	}
}
