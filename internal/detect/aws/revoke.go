package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Provider by deactivating each key through
// iam:UpdateAccessKey, signed with the key itself. AWS has no endpoint for
// reporting a leaked key, so this is best effort: it works for the key of an
// IAM user who may manage their own access keys, and says clearly when it
// does not. A deactivated key can be re-enabled by its owner; deleting it
// for good is left to them. There is no dry run, IAM has none.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	var errs []error
	for _, tok := range tokens {
		if err := p.deactivate(ctx, tok); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", detect.Redact(tok.Value), err))
		}
	}
	return errors.Join(errs...)
}

func (p *Provider) deactivate(ctx context.Context, tok detect.Token) error {
	secret, session := credentials(tok)
	switch {
	case tok.Kind == KindTemporaryKey:
		return errors.New("temporary keys cannot be deactivated; they expire on their own, or revoke the role's sessions in the IAM console")
	case secret == "":
		return errors.New("secret not found near the key id; deactivate it in the IAM console")
	}
	id, err := p.sts(tok.Value, secret, session).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return apiError(err)
	}
	user, err := userName(sdk.ToString(id.Arn))
	if err != nil {
		return err
	}
	_, err = p.iam(tok.Value, secret, session).UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		AccessKeyId: sdk.String(tok.Value),
		Status:      types.StatusTypeInactive,
		UserName:    sdk.String(user),
	})
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "AccessDenied" {
		return errors.New("this key is not allowed to deactivate itself; deactivate it in the IAM console")
	}
	return apiError(err)
}

// userName extracts the user name from the ARN of an IAM user,
// arn:aws:iam::123456789012:user/path/name. Roles, federated users and the
// root user have no access key iam:UpdateAccessKey could deactivate.
func userName(arn string) (string, error) {
	_, resource, ok := strings.Cut(arn, ":user/")
	if !ok {
		return "", fmt.Errorf("%s is not an IAM user, only a user's own key can be deactivated this way; revoke the role's sessions or the root key in the IAM console instead", arn)
	}
	return resource[strings.LastIndexByte(resource, '/')+1:], nil
}

func (p *Provider) iam(id, secret, session string) *iam.Client {
	return iam.New(iam.Options{
		Region:       region,
		BaseEndpoint: sdk.String(p.IAMURL),
		Credentials:  static(id, secret, session),
		HTTPClient:   p.Client,
		Retryer:      sdk.NopRetryer{},
		APIOptions:   []func(*middleware.Stack) error{awsmiddleware.AddUserAgentKey(detect.UserAgent)},
	})
}
