package keyman

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/keyman/certimporter"
)

const (
	ROOT_CERT_STORE_NAME = "ROOT"
)

var (
	cebe *byteexec.Exec
)

func init() {
	exe, err := certimporter.Asset("certimporter.exe")
	if err != nil {
		panic(fmt.Errorf("Unable to get certimporter.exe: %s", err))
	}
	cebe, err = byteexec.New(exe, "certimporter")
	if err != nil {
		panic(fmt.Errorf("Unable to construct executable from memory: %s", err))
	}
}

func DeleteTrustedRootByName(commonName string, prompt string) error {
	cmd := elevatedIfNecessary(prompt)(cebe.Filename, "delete", ROOT_CERT_STORE_NAME, commonName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run certimporter.exe: %s\n%s", err, out)
	}
	return nil
}

func IsInstalled(cert *Certificate) (bool, error) {
	// TODO: make sure that passing byte strings of various encodings to the
	// certimporter program works in different languages/different usernames (
	// which end up in the temp path, etc.)
	cmd := cebe.Command("find", ROOT_CERT_STORE_NAME, cert.X509().Subject.CommonName)
	err := cmd.Run()

	// Consider the certificate found if and only if certimporter.exe exited
	// with a 0 exit code.  Any non-zero code (cert not found, or error looking
	// for cert) is treated as the cert not being found.
	found := err == nil
	return found, nil
}

// AddAsTrustedRootIfNeeded adds the certificate to the user's trust store as a trusted
// root CA.
func (cert *Certificate) AddAsTrustedRootIfNeeded(elevatePrompt, installPromptTitle, installPromptContent string) error {
	if IsInstalled(cert) {
		return nil
	}
	// Warn the user of what's about to happen
	if installPromptContent != "" && installPromptTitle != "" {
		cmd := exec.Command("mshta", fmt.Sprintf("javascript: var sh=new ActiveXObject('WScript.Shell'); sh.Popup('%v', 0, '%v', 64); close()", installPromptContent, installPromptTitle))
		promptErr := cmd.Run()
		if promptErr != nil {
			installErr = fmt.Errorf("Unable to show windows prompt for installing certificate: %v", promptErr)
			return installErr
		}
	}
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
	cmd := elevatedIfNecessary(elevatePrompt)(cebe.Filename, "add", ROOT_CERT_STORE_NAME, tempFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run certimporter.exe: %s\n%s", err, out)
	} else {
		return nil
	}
}
