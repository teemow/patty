// Package aws is the AWS credential provider: the access keys of IAM users
// and the temporary access keys STS hands out.
//
// A key id carries no checksum, but its base32 body encodes the account it
// belongs to, which patty decodes offline. A key id is useless without its
// secret access key, so Find looks for that next to the id, and for the
// session token of a temporary key. Only a complete pair can be verified,
// with one sts:GetCallerIdentity call, or deactivated, with
// iam:UpdateAccessKey on its own user. Both calls are signed with the key
// itself and are recorded in the owner's CloudTrail, which is intended: the
// owner sees that the key was checked.
package aws

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for AWS.
type Provider struct {
	// STSURL and IAMURL are the service endpoints, the global ones by
	// default; tests point them at a local server.
	STSURL string
	IAMURL string
	Client *http.Client
}

const (
	usersPage = "https://console.aws.amazon.com/iam/home#/users"
	rolesPage = "https://console.aws.amazon.com/iam/home#/roles"
)

// auditNote is what to check after a key leaked, whether or not it is dead
// by now.
const auditNote = "check CloudTrail for use of the key since the commit date; a key found in a public GitHub repository gets the AWSCompromisedKeyQuarantine policy attached by AWS, which limits what it may do but does not deactivate it"

// New returns a Provider against the public AWS endpoints.
func New() *Provider {
	return &Provider{STSURL: "https://sts.amazonaws.com", IAMURL: "https://iam.amazonaws.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "AWS" }

// Kinds implements detect.Provider. An access key is revocable in the sense
// that patty can deactivate a key pair through the key's own user, when the
// user may manage its own keys; Revoke says so clearly when it may not.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindAccessKey, Description: "access key", Revocable: true, RevokePage: usersPage,
			RevokeNote: "a key id found without its secret cannot be verified, treat it as live: deactivate it under the user's Security credentials or with `aws iam update-access-key --access-key-id <id> --status Inactive`, then `aws iam delete-access-key`",
			AuditNote:  auditNote},
		{Kind: KindTemporaryKey, Description: "temporary access key (STS)", RevokePage: rolesPage,
			RevokeNote: "STS keys expire on their own within hours; find and stop the process or role session that minted it, or use Revoke sessions on the role",
			AuditNote:  auditNote},
	}
}

// LocalSources implements detect.Provider: the environment variables every
// AWS SDK reads, the shared credentials and config files, and the
// configuration of s3cmd and rclone. Only the key id can match; the secret
// and session token are listed because that is where a pair lives.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
		ConfigFiles: []string{"rclone/rclone.conf"},
		HomeFiles:   []string{".aws/credentials", ".aws/config", ".s3cfg", ".config/rclone/rclone.conf"},
	}
}
