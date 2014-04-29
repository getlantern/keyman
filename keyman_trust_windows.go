package keyman

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/getlantern/keyman/certimporter"
	"github.com/oxtoacart/byteexec"
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
	err = cert.WriteToDERFile(tempFile.Name())
	if err != nil {
		return fmt.Errorf("Unable to save certificate to temp file: %s", err)
	}

	// Add it as a trusted cert
	exe, err := certimporter.Asset("certimporter.exe")
	if err != nil {
		return fmt.Errorf("Unable to get certimporter.exe: %s", err)
	}
	be, err := byteexec.NewByteExec(exe)
	if err != nil {
		return fmt.Errorf("Unable to construct executable from memory: %s", err)
	}
	defer be.Close()
	cmd := be.Command(tempFile.Name(), "ROOT")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run certimporter.exe: %s\n%s", err, out)
	} else {
		return nil
	}
}

func (cert *Certificate) IsInstalled() (bool, error) {
	return false, fmt.Errorf("IsInstalled is not supported on this platform")
}
