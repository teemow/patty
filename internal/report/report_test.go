package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/providers"
	"github.com/teemow/patty/internal/detect/slack"
	"github.com/teemow/patty/internal/gitrepo"
	"github.com/teemow/patty/internal/scan"
)

var registry = providers.Default()

func sample() []scan.Result {
	active := &detect.Verification{Status: detect.StatusActive, Detail: "user patty"}
	commit := &gitrepo.Commit{SHA: "c7655d84dc84a8ac407f36d3cbc562f50e5dfe8a", Author: "Patty", Date: "2026-09-10T11:47:06+02:00", Subject: "add env"}
	return []scan.Result{
		{
			Target: "acme/app",
			Findings: []scan.Finding{
				{Provider: "GitHub", Kind: github.KindOAuth, Fingerprint: "bbbb", Token: "gho_SECRET", Redacted: "gho_S…T", ChecksumVerified: true,
					Locations: []scan.Location{{Repo: "acme/app", Path: "deploy.sh", Line: 3, ObjectType: "blob", Commit: commit, Refs: []string{"refs/heads/main", "refs/pull/7/head", "refs/pull/7/merge", "refs/tags/v1"}}}},
				{Provider: "GitHub", Kind: github.KindPAT, Fingerprint: "aaaa", Token: "ghp_SECRET", Redacted: "ghp_S…T", ChecksumVerified: true, Verification: active,
					Locations: []scan.Location{{Repo: "acme/app", Path: ".env", Line: 1, ObjectType: "blob", Commit: commit, Orphaned: true, Rewrite: "force-pushed away from main on 2026-09-10"}}},
			},
			Stats: scan.Stats{Scanned: 10, Bytes: 2048},
		},
		{
			Target: "acme/lib",
			Findings: []scan.Finding{
				{Provider: "GitHub", Kind: github.KindPAT, Fingerprint: "aaaa", Token: "ghp_SECRET", Redacted: "ghp_S…T", ChecksumVerified: true, Verification: active,
					Locations: []scan.Location{{Repo: "acme/lib", ObjectType: "commit", Commit: commit, Refs: []string{"refs/heads/dev"}}}},
			},
		},
		{Target: "acme/huge", Skipped: true, Err: errors.New("disk budget: too big"), Error: "disk budget: too big"},
	}
}

func TestTextMergesAcrossReposAndRedacts(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sample(), Options{})
	out := buf.String()
	if strings.Contains(out, "SECRET") {
		t.Fatalf("secrets must be redacted:\n%s", out)
	}
	if !strings.Contains(out, "2 credentials found (1 active)") || !strings.Contains(out, "in 3 repositories, 1 skipped") {
		t.Fatalf("header wrong:\n%s", out)
	}
	// The active token comes first and lists both repositories.
	if strings.Index(out, "ACTIVE") > strings.Index(out, "unverified") {
		t.Fatalf("active token must be listed first:\n%s", out)
	}
	for _, want := range []string{"acme/app  .env:1", "acme/lib  commit message", "orphaned", "force-pushed away from main", "on main, tag v1, PR #7", "c7655d84 2026-09-10 Patty"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	buf.Reset()
	Text(&buf, sample(), Options{ShowSecrets: true})
	if !strings.Contains(buf.String(), "ghp_SECRET") {
		t.Fatal("--show-secrets must print the value")
	}

	buf.Reset()
	Text(&buf, nil, Options{})
	if !strings.Contains(buf.String(), "No credentials found") {
		t.Fatal("empty report")
	}
}

func TestStatusLine(t *testing.T) {
	rs := sample()
	if s := StatusLine(rs[0], Options{}); !strings.HasPrefix(s, "! acme/app") || !strings.Contains(s, "2 credentials") {
		t.Fatalf("findings line: %q", s)
	}
	if s := StatusLine(rs[2], Options{}); !strings.HasPrefix(s, "– acme/huge") || !strings.Contains(s, "skipped: disk budget") {
		t.Fatalf("skipped line: %q", s)
	}
	if s := StatusLine(scan.Result{Target: "x", Err: errors.New("boom"), Notes: []string{"n"}}, Options{}); !strings.HasPrefix(s, "✘ x") || !strings.Contains(s, "note: n") {
		t.Fatalf("failed line: %q", s)
	}
	if s := StatusLine(scan.Result{Target: "ok"}, Options{Color: true}); !strings.Contains(s, "\033[32m✔") {
		t.Fatalf("color: %q", s)
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample(), Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "SECRET") {
		t.Fatal("JSON must redact by default")
	}
	var out Output
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.Tokens != 2 || out.Summary.Active != 1 || out.Summary.Skipped != 1 || out.Summary.Repositories != 3 {
		t.Fatalf("summary: %+v", out.Summary)
	}
	if out.Results[0].Target != "acme/app" || out.Results[2].Error == "" || out.Results[2].Findings == nil {
		t.Fatalf("results: %+v", out.Results)
	}
	buf.Reset()
	_ = JSON(&buf, sample(), Options{ShowSecrets: true})
	if !strings.Contains(buf.String(), `"token": "ghp_SECRET"`) {
		t.Fatal("--show-secrets in JSON")
	}
}

func TestRefs(t *testing.T) {
	got := Refs([]string{"refs/pull/1/head", "refs/pull/1/merge", "refs/heads/feature", "refs/tags/v2", "refs/heads/main", "refs/remotes/origin/x", "refs/other"}, 4)
	if got != "main, feature, origin/x, tag v2, +2 more" {
		t.Fatalf("Refs = %q", got)
	}
	loc := scan.Location{Commit: &gitrepo.Commit{}, Refs: []string{"refs/pull/3/head", "refs/pull/3/merge", "refs/pull/9/head"}}
	if got := reachability(loc, Options{}); got != "not on any branch or tag, only reachable through pull request refs: PR #3, PR #9" {
		t.Fatalf("reachability = %q", got)
	}
}

func TestTextIssuerLocalAndRemediation(t *testing.T) {
	rs := sample()
	rs[0].Findings[1].Verification = &detect.Verification{Status: detect.StatusActive, Detail: "user patty", ClientID: "178c6fc778ccc68e1d6a", App: "GitHub CLI", Expires: "2026-10-01"}
	rs[0].Findings[1].Local = []string{"~/.config/gh/hosts.yml"}
	var buf bytes.Buffer
	Text(&buf, rs, Options{})
	out := buf.String()
	for _, want := range []string{
		"user patty  issued to GitHub CLI  expires 2026-10-01",
		"↳ revoke   at https://github.com/settings/tokens under GitHub CLI; or run again with --revoke",
		"↳ local    still configured in ~/.config/gh/hosts.yml; replace it there after revoking",
		"↳ history  acme/app: in orphaned commits GitHub still serves by SHA (GitHub Support can purge them) · acme/lib: in branch history (rewrite with git filter-repo, then force-push) · forks made in the meantime keep their own copy",
		"↳ revoke   if it is still valid, at https://github.com/settings/applications; or with --verify --revoke",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRemediationStates(t *testing.T) {
	loc := []scan.Location{{Repo: "r", Commit: &gitrepo.Commit{}, Refs: []string{"refs/pull/1/head"}}}
	revoked := scan.Finding{Kind: github.KindPAT, Verification: &detect.Verification{Status: detect.StatusRevoked}, Local: []string{"~/.config/hub"}, Locations: loc}
	if steps := Remediation(revoked, registry); len(steps) != 0 {
		t.Fatalf("revoked token needs nothing, got %+v", steps)
	}
	done := scan.Finding{Kind: slack.KindBot, Revocation: scan.RevocationDone, Verification: &detect.Verification{Status: detect.StatusRevoked}, Locations: loc}
	if steps := Remediation(done, registry); len(steps) != 1 || steps[0].Text != "done, Slack rejects it now" {
		t.Fatalf("done: %+v", steps)
	}
	pending := scan.Finding{Kind: github.KindPAT, Revocation: scan.RevocationPending, Verification: &detect.Verification{Status: detect.StatusActive}, Locations: loc}
	steps := Remediation(pending, registry)
	if len(steps) != 2 || !strings.HasPrefix(steps[0].Text, "GitHub accepted the revocation") || steps[1].Label != "history" || !strings.Contains(steps[1].Text, "r: only in pull request refs (GitHub Support has to purge those)") {
		t.Fatalf("pending: %+v", steps)
	}
	app := scan.Finding{Kind: github.KindServerToServer, Verification: &detect.Verification{Status: detect.StatusActive}}
	if steps := Remediation(app, registry); len(steps) != 1 || steps[0].Text != "at https://github.com/settings/installations; installation tokens expire within an hour anyway" {
		t.Fatalf("installation token: %+v", steps)
	}
	hook := scan.Finding{Kind: slack.KindWebhook, Verification: &detect.Verification{Status: detect.StatusActive}}
	if steps := Remediation(hook, registry); len(steps) != 1 || steps[0].Text != "at https://api.slack.com/apps; webhooks are removed under the app's Incoming Webhooks, or in Workflow Builder for workflow webhooks" {
		t.Fatalf("webhook: %+v", steps)
	}
	bot := scan.Finding{Kind: slack.KindBot, Verification: &detect.Verification{Status: detect.StatusActive}}
	if steps := Remediation(bot, registry); len(steps) != 1 || steps[0].Text != "at https://api.slack.com/apps; or run again with --revoke" {
		t.Fatalf("bot: %+v", steps)
	}
}

func TestTextShowsAttributionPerProvider(t *testing.T) {
	rs := []scan.Result{{Target: "acme/ops", Findings: []scan.Finding{
		{Provider: "Slack", Kind: slack.KindBot, Fingerprint: "cccc", Token: "xoxb-SECRET", Redacted: "xoxb-S…T", Attribution: "team 1234567890, bot 1234567890123",
			Locations: []scan.Location{{Repo: "acme/ops", Path: "bot.env", Line: 2, ObjectType: "blob", Commit: &gitrepo.Commit{SHA: "abcdef0123456789", Date: "2026-09-10T11:47:06+02:00"}, Refs: []string{"refs/heads/main"}}}},
	}}}
	var buf bytes.Buffer
	Text(&buf, rs, Options{})
	out := buf.String()
	for _, want := range []string{"1 credential found", "slack-bot-token", "team 1234567890, bot 1234567890123", "(shape match, no checksum)", "↳ revoke   if it is still valid, at https://api.slack.com/apps; or with --verify --revoke"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SECRET") {
		t.Fatalf("secrets must be redacted:\n%s", out)
	}
}

func TestAllRefs(t *testing.T) {
	refs := []string{"refs/heads/a", "refs/heads/b", "refs/heads/c", "refs/heads/d", "refs/heads/e", "refs/heads/f", "refs/heads/g"}
	loc := scan.Location{Commit: &gitrepo.Commit{}, Refs: refs}
	if got := reachability(loc, Options{}); got != "on a, b, c, d, e, +2 more" {
		t.Fatalf("default = %q", got)
	}
	if got := reachability(loc, Options{AllRefs: true}); got != "on a, b, c, d, e, f, g" {
		t.Fatalf("all = %q", got)
	}
}
