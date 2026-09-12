package aws

import (
	"context"
	"errors"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"

	"github.com/teemow/patty/internal/detect"
)

// region signs the requests to the global STS and IAM endpoints.
const region = "us-east-1"

// Verify implements detect.Provider with one sts:GetCallerIdentity call
// signed with the key pair; the call needs no permission and every key can
// make it. It is recorded in the owner's CloudTrail, which is intended. A
// key id without its secret, or a temporary key without its session token,
// cannot be checked at all.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	secret, session := credentials(tok)
	switch {
	case secret == "":
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "secret not found near the key id"}
	case tok.Kind == KindTemporaryKey && session == "":
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "session token not found near the key id; a temporary key is only accepted together with it"}
	}
	out, err := p.sts(tok.Value, secret, session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return classify(err, tok.Kind)
	}
	return detect.Verification{Status: detect.StatusActive, Detail: sdk.ToString(out.Arn) + ", account " + sdk.ToString(out.Account)}
}

// classify turns an STS error into a verdict. Only the explicit
// invalid-credentials answers count as revoked; anything else is unknown.
func classify(err error, kind detect.Kind) detect.Verification {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	switch api.ErrorCode() {
	case "InvalidClientTokenId":
		detail := "key deleted or deactivated"
		if kind == KindTemporaryKey {
			detail = "session token no longer accepted"
		}
		return detect.Verification{Status: detect.StatusRevoked, Detail: detail}
	case "SignatureDoesNotMatch":
		return detect.Verification{Status: detect.StatusUnknown, Detail: "key id exists but the secret found next to it is not its secret"}
	case "ExpiredToken", "ExpiredTokenException":
		if kind == KindTemporaryKey {
			return detect.Verification{Status: detect.StatusRevoked, Detail: "expired"}
		}
	}
	return detect.Verification{Status: detect.StatusUnknown, Detail: api.ErrorCode() + ": " + api.ErrorMessage()}
}

// sts returns an STS client that signs with the given key and makes exactly
// one request per call: a verification is never retried.
func (p *Provider) sts(id, secret, session string) *sts.Client {
	return sts.New(sts.Options{
		Region:       region,
		BaseEndpoint: sdk.String(p.STSURL),
		Credentials:  static(id, secret, session),
		HTTPClient:   p.Client,
		Retryer:      sdk.NopRetryer{},
		APIOptions:   []func(*middleware.Stack) error{awsmiddleware.AddUserAgentKey(detect.UserAgent)},
	})
}

func static(id, secret, session string) sdk.CredentialsProvider {
	return sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
		return sdk.Credentials{AccessKeyID: id, SecretAccessKey: secret, SessionToken: session}, nil
	})
}

// apiError shortens an SDK error to the service's code and message, which
// is what the user can act on.
func apiError(err error) error {
	var api smithy.APIError
	if errors.As(err, &api) {
		return errors.New(api.ErrorCode() + ": " + api.ErrorMessage())
	}
	return err
}
