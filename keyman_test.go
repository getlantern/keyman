package keyman

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(time.Now().Nanosecond())),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "commonname.com",
		},
		NotBefore: now.Add(-1 * ONE_WEEK),
		NotAfter:  now.Add(TWO_WEEKS),

		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	cert, err := pk.TLSCertificateFor("Test Org", "127.0.0.1", TWO_WEEKS, nil)
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

	_, err = pk.Certificate(template, cert)
	if err != nil {
		t.Fatalf("Unable to generate certificate signed by original certificate")
	}
}
