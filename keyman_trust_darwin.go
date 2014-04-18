package keyman

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
)

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA.
func (cert *Certificate) AddAsTrustedRoot() error {
	// Get user's home folder
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("Unable to determine current user: %s", err)
	}

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
	cmd := exec.Command("security", "add-trusted-cert", "-k", usr.HomeDir+"/Library/Keychains/login.keychain", tempFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run security command: %s\n%s", err, out)
	} else {
		return nil
	}
}
