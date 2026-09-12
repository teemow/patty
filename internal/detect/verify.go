package detect

// VerifyStatus is the outcome of checking a credential against its provider.
type VerifyStatus string

const (
	// StatusActive means the provider accepted the credential: it is live and must be revoked.
	StatusActive VerifyStatus = "active"
	// StatusRevoked means the provider explicitly rejected the credential as invalid.
	StatusRevoked VerifyStatus = "revoked"
	// StatusUnverifiable means the credential family cannot be checked without side effects.
	StatusUnverifiable VerifyStatus = "unverifiable"
	// StatusUnknown means the check could not be completed (network, rate
	// limit, an unexpected answer). It is never treated as proof of anything.
	StatusUnknown VerifyStatus = "unknown"
)

// Verification is the result of Provider.Verify.
type Verification struct {
	Status VerifyStatus `json:"status"`
	// Detail describes what the credential gives access to: user and scopes,
	// the workspace of a Slack token, the number of repositories an
	// installation token reaches.
	Detail string `json:"detail,omitempty"`
	// ClientID is the id of the application the credential was issued to,
	// when the provider reports one.
	ClientID string `json:"client_id,omitempty"`
	// App is the name of that application when patty knows the client id.
	App string `json:"app,omitempty"`
	// Expires is when the credential stops working, for credentials that expire.
	Expires string `json:"expires,omitempty"`
}

// Issuer names the application a credential was issued to: the known app
// name, else the raw client id, else "".
func (v Verification) Issuer() string {
	if v.App != "" {
		return v.App
	}
	if v.ClientID != "" {
		return "OAuth app " + v.ClientID
	}
	return ""
}
