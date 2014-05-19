package keyman

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"
)

const (
	PK_FILE   = "testpk.pem"
	CERT_FILE = "testcert.pem"

	ONE_WEEK  = 7 * 24 * time.Hour
	TWO_WEEKS = ONE_WEEK * 2
)

func TestRoundTrip(t *testing.T) {
	defer os.Remove(PK_FILE)
	defer os.Remove(CERT_FILE)

	pk, err := GeneratePK(1024)
	if err != nil {
		t.Fatalf("Unable to generate PK: %s", err)
	}

	err = pk.WriteToFile(PK_FILE)
	if err != nil {
		t.Fatalf("Unable to save PK: %s", err)
	}

	pk2, err := LoadPKFromFile(PK_FILE)
	if err != nil {
		t.Fatalf("Unable to load PK: %s", err)
	}

	if !bytes.Equal(pk.PEMEncoded(), pk2.PEMEncoded()) {
		t.Errorf("Loaded PK didn't match saved PK\nSaved\n------------%s\n\nLoaded\n------------%s", pk.PEMEncoded(), pk2.PEMEncoded())
	}

	cert, err := pk.TLSCertificateFor("Test Org", "127.0.0.1", time.Now().Add(TWO_WEEKS), true, nil)
	if err != nil {
		t.Fatalf("Unable to generate self-signed certificate: %s", err)
	}

	numberOfIPSANs := len(cert.X509().IPAddresses)
	if numberOfIPSANs != 1 {
		t.Errorf("Wrong number of SANs, expected 1 got %d", numberOfIPSANs)
	} else {
		ip := cert.X509().IPAddresses[0]
		expectedIP := net.ParseIP("127.0.0.1")
		if ip.String() != expectedIP.String() {
			t.Errorf("Wrong IP SAN.  Expected %s, got %s", expectedIP, ip)
		}
	}

	err = cert.WriteToFile(CERT_FILE)
	if err != nil {
		t.Fatalf("Unable to write certificate to file: %s", err)
	}

	cert2, err := LoadCertificateFromFile(CERT_FILE)
	if err != nil {
		t.Fatalf("Unable to load certificate from file: %s")
	}

	if !bytes.Equal(cert2.PEMEncoded(), cert.PEMEncoded()) {
		t.Errorf("Loaded certificate didn't match saved certificate\nSaved\n------------%s\n\nLoaded\n------------%s", cert.PEMEncoded(), cert2.PEMEncoded())
	}

	_, err = pk.Certificate(cert.X509(), cert)
	if err != nil {
		t.Fatalf("Unable to generate certificate signed by original certificate")
	}
}
