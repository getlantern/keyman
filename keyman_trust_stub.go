// +build !darwin,!windows,!linux

package keyman

import (
	"fmt"
)

// InstallToUserKeyChain adds the certificate to the user's keychain.
func (cert *Certificate) InstallToUserKeyChain() error {
	return fmt.Errorf("AddToUserTrustStore is not supported on this platform")
}

func (cert *Certificate) IsInstalled() (bool, error) {
	return false, fmt.Errorf("IsInstalled is not supported on this platform")
}
