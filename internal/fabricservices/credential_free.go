package fabricservices

import (
	"context"
	"crypto/sha256"
	"github.com/pagnet-code/pagnet/fabric"
)

// CredentialFreeAccountDigest commits to explicit absence of credentials. It
// is not a user identity, token or permission, and never inspects ambient env.
func CredentialFreeAccountDigest() [32]byte {
	return sha256.Sum256([]byte("pagnet.service.credentials.none.v1"))
}

type CredentialFreeProvider struct{}

func (CredentialFreeProvider) Resolve(ctx context.Context, selector string) (Credentials, error) {
	if ctx == nil {
		return Credentials{}, denied()
	}
	if e := ctx.Err(); e != nil {
		return Credentials{}, e
	}
	if selector != "none" {
		return Credentials{}, fabric.NewError(fabric.CodeUnsupported, "This configured provider supports only explicit credential-free profiles")
	}
	return Credentials{BindingDigest: CredentialFreeAccountDigest()}, nil
}
