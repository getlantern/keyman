// +build !darwin,!windows

package keyman

import (
	"fmt"
)

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA.
func (cert *Certificate) AddAsTrustedRoot() error {
	return fmt.Errorf("AddToUserTrustStore is not supported on this platform")
}
