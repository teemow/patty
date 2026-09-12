package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestRevokeDeactivatesTheKeyThroughItsUser(t *testing.T) {
	p, calls := server(t)
	ctx := context.Background()
	tokens := []detect.Token{pairOf(KindAccessKey, "live-user", mixed), pairOf(KindAccessKey, "live-path", mixed)}
	if err := p.Revoke(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	made := calls()
	if len(made) != 4 {
		t.Fatalf("want identity then update per key, got %+v", made)
	}
	for i, user := range []string{"alice", "deploy"} {
		id, up := made[2*i], made[2*i+1]
		if id.action != "GetCallerIdentity" || id.keyID != tokens[i].Value {
			t.Errorf("first call: %+v", id)
		}
		if up.action != "UpdateAccessKey" || up.keyID != tokens[i].Value || up.form["AccessKeyId"] != tokens[i].Value || up.form["Status"] != "Inactive" || up.form["UserName"] != user || up.form["Version"] != "2010-05-08" {
			t.Errorf("update call: %+v", up)
		}
	}
	for _, tok := range tokens {
		if v := p.Verify(ctx, tok); v.Status != detect.StatusRevoked {
			t.Errorf("%s after deactivation: %+v", tok.Value, v)
		}
	}
}

func TestRevokeRefusals(t *testing.T) {
	p, calls := server(t)
	ctx := context.Background()
	cases := []struct {
		name  string
		tok   detect.Token
		want  string
		calls int
	}{
		{"temporary", pairOf(KindTemporaryKey, "live-role", mixed+"\n"+long), "temporary keys cannot be deactivated", 0},
		{"id only", detect.Token{Kind: KindAccessKey, Value: "live-user"}, "secret not found near the key id", 0},
		{"role", pairOf(KindAccessKey, "live-role", mixed), "arn:aws:sts::123456789012:assumed-role/Deploy/i-0abc is not an IAM user", 1},
		{"root", pairOf(KindAccessKey, "live-root", mixed), "arn:aws:iam::123456789012:root is not an IAM user", 1},
		{"access denied", pairOf(KindAccessKey, "live-denied", mixed), "this key is not allowed to deactivate itself; deactivate it in the IAM console", 2},
		{"already dead", pairOf(KindAccessKey, "dead", mixed), "InvalidClientTokenId: The security token included in the request is invalid.", 1},
		{"wrong secret", pairOf(KindAccessKey, "wrongsecret", mixed), "SignatureDoesNotMatch: ", 1},
	}
	for _, c := range cases {
		before := len(calls())
		err := p.Revoke(ctx, []detect.Token{c.tok})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && (!strings.HasPrefix(err.Error(), detect.Redact(c.tok.Value)+": ") || strings.Contains(err.Error(), mixed)) {
			t.Errorf("%s: errors name the key redacted and never the secret: %v", c.name, err)
		}
		if n := len(calls()) - before; n != c.calls {
			t.Errorf("%s: %d calls, want %d", c.name, n, c.calls)
		}
	}
	err := p.Revoke(ctx, []detect.Token{pairOf(KindAccessKey, "live-denied", mixed), pairOf(KindAccessKey, "live-user", mixed)})
	if err == nil || !strings.Contains(err.Error(), "not allowed to deactivate itself") || strings.Count(err.Error(), "\n") != 0 {
		t.Fatalf("one refusal does not stop the others and is reported alone: %v", err)
	}
	if err := p.Revoke(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestUserName(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:user/alice":               "alice",
		"arn:aws:iam::123456789012:user/ops/tools/deploy":    "deploy",
		"arn:aws-cn:iam::123456789012:user/a":                "a",
		"arn:aws:iam::123456789012:root":                     "",
		"arn:aws:sts::123456789012:assumed-role/R/s":         "",
		"arn:aws:sts::123456789012:federated-user/user/name": "",
		"": "",
	} {
		got, err := userName(arn)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("userName(%q) = %q, %v", arn, got, err)
		}
	}
}
