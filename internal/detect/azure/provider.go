// Package azure is the Microsoft Azure credential provider: the client
// secrets of Entra ID applications (service principals), storage account
// keys, and shared access signatures.
//
// None of the three carries a checksum, and only the client secret has a
// shape of its own, the `Q~` at its fifth character. A secret is useless
// without the tenant and the application it belongs to, and a storage key
// without its account, so Find looks for those next to the credential and
// keeps them apart in Token.Secret; the report says what it found.
// Verification is one client-credentials request to the tenant's token
// endpoint, one signed listing of the storage account's containers, or one
// HEAD of the resource a signature is for. Nothing here can be revoked by
// whoever holds it: the owner deletes the secret, rotates the key or the
// key that signed the signature, and the report carries the procedures.
package azure

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for Azure.
type Provider struct {
	// LoginURL is the Entra ID authority, https://login.microsoftonline.com
	// by default; the tenant's token endpoint hangs off it.
	LoginURL string
	// BlobEndpoint is where a storage account's blob service is reached,
	// with {account} standing for the account name.
	BlobEndpoint string
	Client       *http.Client
	// now is the clock signatures and expiries are compared against; tests
	// fix it.
	now func() time.Time
}

const (
	appsPage = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"
	// storagePage lists the storage accounts; the key is rotated under the
	// account's Access keys.
	storagePage = "https://portal.azure.com/#browse/Microsoft.Storage%2FStorageAccounts"
)

// partnerNote is what Azure does on its own: it is a GitHub secret scanning
// partner for client secrets and storage keys, but nothing says a leaked
// one was disabled.
const partnerNote = "Azure is a GitHub secret scanning partner for client secrets and storage keys, but do not assume anything was disabled: confirm with --verify"

// New returns a Provider against the public Azure endpoints.
func New() *Provider {
	return &Provider{
		LoginURL:     "https://login.microsoftonline.com",
		BlobEndpoint: "https://{account}.blob.core.windows.net",
		Client:       &http.Client{Timeout: 30 * time.Second},
		now:          time.Now,
	}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Azure" }

// Kinds implements detect.Provider. Nothing is revocable by the holder;
// every kind carries the owner's procedure.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindClientSecret, Description: "Entra ID application (service principal) client secret", RevokePage: appsPage,
			RevokeNote: "under the app registration's Certificates & secrets, or `az ad app credential delete --id <clientId> --key-id <keyId>`; the key id is not in the secret, `az ad app credential list --id <clientId>` shows it",
			AuditNote:  "check the Entra sign-in logs for the service principal since the commit date; " + partnerNote},
		{Kind: KindStorageAccountKey, Description: "storage account access key", RevokePage: storagePage,
			RevokeNote: "under the account's Access keys → Rotate key, or `az storage account keys renew --account-name <name> --key primary` (or secondary; both keys grant full access, rotate the leaked one first, then the other); every SAS signed with the key dies with it",
			AuditNote:  "check the storage account's diagnostic logs (StorageBlobLogs and the other tables) for requests authenticated with Shared Key since the commit date; " + partnerNote},
		{Kind: KindSASToken, Description: "shared access signature", RevokePage: storagePage,
			RevokeNote: "a SAS cannot be revoked on its own: rotate the account key that signed it (Access keys → Rotate key), or for a SAS bound to a stored access policy delete that policy; a user delegation SAS is revoked with `az storage account revoke-delegation-keys`",
			AuditNote:  "check the storage account's diagnostic logs for requests authenticated with SAS since the commit date; an expired signature is no longer accepted, which the report says"},
	}
}

// LocalSources implements detect.Provider: the files the Azure CLI keeps
// service principal logins and tokens in, and the variables the SDKs,
// Terraform and the storage tools read. The tenant, client and account
// variables hold no secret but are listed so a secret or key next to them
// is paired the way it is in an .env file. Only fingerprints are compared.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env: []string{
			"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "ARM_TENANT_ID", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET",
			"AZURE_STORAGE_ACCOUNT", "AZURE_STORAGE_KEY", "AZURE_STORAGE_CONNECTION_STRING", "AZURE_STORAGE_SAS_TOKEN",
		},
		HomeFiles: []string{".azure/service_principal_entries.json", ".azure/msal_token_cache.json"},
	}
}
