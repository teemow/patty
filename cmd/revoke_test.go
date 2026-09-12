package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/scan"
)

func token(kind byte, random string) string {
	return "gh" + string(kind) + "_" + random + detect.Checksum(random)
}

func TestParseTokens(t *testing.T) {
	pat := token('p', "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	app := token('s', "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	input := "leaked: " + pat + "\n" + pat + "\nnot-a-token gh" + "p_short\n" + app + "\n"
	got := parseTokens(input)
	if len(got) != 2 || got[0].Value != pat || got[1].Kind != detect.KindServerToServer {
		t.Fatalf("parseTokens = %+v", got)
	}
}

func TestRevokeRefusesWithoutTerminalOrYes(t *testing.T) {
	cmd := &cobra.Command{}
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader("y\n"))
	opts.yes = false
	if ok, err := confirm(cmd, "? "); ok || err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("confirm = %v, %v", ok, err)
	}
	opts.yes = true
	defer func() { opts.yes = false }()
	if ok, err := confirm(cmd, "? "); !ok || err != nil {
		t.Fatalf("--yes must confirm: %v, %v", ok, err)
	}

	// The subcommand itself refuses installation tokens and empty input before touching the network.
	rc, _, _ := rootCmd.Find([]string{"revoke"})
	rc.SetIn(strings.NewReader("nothing here"))
	rc.SetErr(&stderr)
	if err := runRevoke(rc, nil); err == nil || err.Error() != "no GitHub tokens in the input" {
		t.Fatalf("empty: %v", err)
	}
	rc.SetIn(strings.NewReader(token('s', "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")))
	if err := runRevoke(rc, nil); err == nil || err.Error() != "nothing to revoke" || !strings.Contains(stderr.String(), "cannot be revoked through the API") {
		t.Fatalf("installation token: %v\n%s", err, stderr.String())
	}
}

func TestWarnings(t *testing.T) {
	cli := scan.Finding{Kind: detect.KindOAuth, Verification: &detect.Verification{App: "GitHub CLI"}, Local: []string{"~/.config/gh/hosts.yml"}}
	got := warnings(cli)
	if len(got) != 2 || !strings.Contains(got[0], "whole authorization of GitHub CLI") || !strings.Contains(got[1], "~/.config/gh/hosts.yml") {
		t.Fatalf("warnings = %q", got)
	}
	if got := warnings(scan.Finding{Kind: detect.KindPAT}); len(got) != 0 {
		t.Fatalf("plain PAT has no warnings: %q", got)
	}
	if got := warnings(scan.Finding{Kind: detect.KindUserToServer}); len(got) != 1 || !strings.Contains(got[0], "this application") {
		t.Fatalf("unknown app: %q", got)
	}
}
