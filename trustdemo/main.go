package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/getlantern/keyman"
)

const (
	commonName = "trustdemo.getlantern.org"
)

func main() {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		log.Fatalf("Unable to generate PK: %v", err)
	}

	cert, err := pk.TLSCertificateFor(time.Now().Add(24*time.Hour), false, nil, "Lantern", commonName, "san1.com", "san2.com")
	if err != nil {
		log.Fatalf("Unable to generate certificate: %v", err)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("mshta", "javascript: var sh=new ActiveXObject('WScript.Shell'); sh.Popup('Please allow certimporter.exe to make changes to your system', 0, 'TrustDemo wants to make change to your system certificates', 64); close()")
		err := cmd.Run()
		if err != nil {
			log.Fatalf("Unable to display introductory prompt")
		}
	}

	err = cert.AddAsTrustedRootIfNeeded(fmt.Sprintf("Please allow trustdemo to install a certificate for %v", commonName), "Prompt Title", "Prompt Body")
	if err != nil {
		log.Fatalf("Unable to add as trusted root: %v", err)
	}

	in := bufio.NewReader(os.Stdin)
	fmt.Printf("Installed certificate with common name %v, hit Enter to continue ...", commonName)
	in.ReadString('\n')

	err = keyman.DeleteTrustedRootByName(commonName, fmt.Sprintf("Please allow trustdemo to uninstall the certificate for %v", commonName))
	if err != nil {
		log.Fatalf("Unable to delete trusted root: %v", err)
	}
	fmt.Printf("Uninstalled certificate with common name %v", commonName)
}
