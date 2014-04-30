package keyman

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

const (
	// TODO: Make sure to handle case where library is on a different path
	OSX_SYSTEM_KEYCHAIN_PATH = "/Library/Keychains/System.keychain"
)

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA.
func (cert *Certificate) AddAsTrustedRoot() error {
	// Create a temp file containing the certificate
	tempFile, err := ioutil.TempFile("", "tempCert")
	defer os.Remove(tempFile.Name())
	if err != nil {
		return fmt.Errorf("Unable to create temp file: %s", err)
	}
	err = cert.WriteToFile(tempFile.Name())
	if err != nil {
		return fmt.Errorf("Unable to save certificate to temp file: %s", err)
	}

	// Add it as a trusted cert
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-k", OSX_SYSTEM_KEYCHAIN_PATH, tempFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run security command: %s\n%s", err, out)
	} else {
		return nil
	}
}

// Checks whether this certificate is install based purely on looking for a cert
// in the system keychain that has the same common name.  This function returns
// true if there are one or more certs in the system keychain whose common name
// matches this cert.
func (cert *Certificate) IsInstalled() (bool, error) {
	cmd := exec.Command("security", "find-certificate", "-c", cert.X509().Subject.CommonName, OSX_SYSTEM_KEYCHAIN_PATH)
	err := cmd.Run()
	return err == nil, nil
}
