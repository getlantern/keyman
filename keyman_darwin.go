// Uses code from this article: http://support.citrix.com/article/CTX124859
package keyman

// #cgo CFLAGS: -w
// #cgo LDFLAGS: -framework Foundation -framework Security
// #include "CertTrustSetter.h"
import "C"

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
)

func (cert *Certificate) AddToUserTrustStore() error {
	var secRef C.SecCertificateRef
	status, err := C.addCertificateWithBytes((*C.uint8)((&cert.derBytes[0])), C.int(len(cert.derBytes)), &secRef)
	if err != nil {
		return fmt.Errorf("Unable to add certificate to trust store: %s", err)
	} else if int(status) != 0 {
		return fmt.Errorf("Unable to add certificate to tust store, status: %d", int(status))
	} else {
		return nil
	}
}

func (cert *Certificate) AddToUserTrustStoreByCmdLine() error {
	// Get user's home folder
	usr, err := user.Current()
	if err != nil {
		return err
	}
	// Create a temp file containing the certificate
	tempFile, err := ioutil.TempFile("", "tempCert")
	defer os.Remove(tempFile.Name())
	if err != nil {
		return err
	}
	err = cert.WriteToFile(tempFile.Name())
	if err != nil {
		return err
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
