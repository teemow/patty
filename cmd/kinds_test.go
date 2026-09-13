package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect/anthropic"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/gitlab"
	"github.com/teemow/patty/internal/detect/grafana"
	"github.com/teemow/patty/internal/detect/kubernetes"
	"github.com/teemow/patty/internal/detect/npm"
	"github.com/teemow/patty/internal/detect/openai"
	"github.com/teemow/patty/internal/detect/providers"
)

func TestWriteKinds(t *testing.T) {
	// The table must not depend on the machine it is generated on.
	t.Setenv(anthropic.AdminKeyEnv, "set-on-this-machine")

	var out bytes.Buffer
	writeKinds(&out)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if lines[0] != "| Provider | Kind | Description | Revocable via API |" || !strings.HasPrefix(lines[1], "|---") {
		t.Fatalf("header:\n%s", out.String())
	}
	rows := lines[2:]

	var total int
	for _, p := range providers.New(func(string) string { return "" }).Providers() {
		for _, k := range p.Kinds() {
			total++
			want := "| " + p.Name() + " | `" + string(k.Kind) + "` | "
			if !hasRowPrefix(rows, want) {
				t.Errorf("no row for %s", want)
			}
		}
	}
	if len(rows) != total {
		t.Fatalf("%d rows for %d kinds", len(rows), total)
	}

	for _, tc := range []struct{ kind, revocable string }{
		{string(github.KindPAT), "yes"},
		{string(github.KindServerToServer), "no"},
		{string(anthropic.KindAPIKey), "with " + anthropic.AdminKeyEnv},
		{string(openai.KindProject), "with " + openai.AdminKeyEnv},
		{string(openai.KindLegacy), "no"},
		{string(kubernetes.KindClientCertificate), "no"}, // no Revoker, whatever KindInfo says
		{string(gitlab.KindPAT), "yes"},
		{string(gitlab.KindDeployToken), "no"},
		{string(grafana.KindServiceAccountToken), "no"}, // Configurable, but the configuration is not what makes anything revocable
		{string(npm.KindAccessToken), "yes"},
	} {
		if !hasRowSuffix(rows, "`"+tc.kind+"`", "| "+tc.revocable+" |") {
			t.Errorf("%s should be revocable %q:\n%s", tc.kind, tc.revocable, out.String())
		}
	}

	// A hidden subcommand, wired into the root.
	c, _, err := rootCmd.Find([]string{"kinds"})
	if err != nil || c.Name() != "kinds" || !c.Hidden {
		t.Fatalf("kinds command: %v, %v", c, err)
	}
}

func hasRowPrefix(rows []string, prefix string) bool {
	for _, r := range rows {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func hasRowSuffix(rows []string, contains, suffix string) bool {
	for _, r := range rows {
		if strings.Contains(r, contains) && strings.HasSuffix(r, suffix) {
			return true
		}
	}
	return false
}
