package registration

import (
	"crypto"

	"github.com/digicert/lego/v5/acme"
)

// User interface is to be implemented by users of this library.
// It is used by the client type to get user specific information.
type User interface {
	GetEmail() string
	GetRegistration() *acme.ExtendedAccount
	GetPrivateKey() crypto.Signer
}
