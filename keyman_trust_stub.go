// +build !darwin,!windows,!linux

package keyman

import (
	"fmt"
)

func DeleteTrustedRootByName(commonName string, prompt string) error {
	return fmt.Errorf("DeleteTrustedRootByName is not supported on this platform")
}

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA. If prompt is provided, privilege escalation will be requested (if
// required) and the user will be prompted with the given text.
func (cert *Certificate) AddAsTrustedRootIfNeeded(prompt string) error {
	return fmt.Errorf("AddAsTrustedRootIfNeeded is not supported on this platform")
}
