// CertImporter.cpp :
// This application imports DER encoded X509 certificates into the current
// user's personal trust store.
//
// certimporter <path_to_certificate> <system store name (e.g. ROOT)>
//
// If and only if the import was successful, this program exits with status 0.

#include "stdafx.h"
#include <windows.h>
#include <Wincrypt.h>
#include <cryptuiapi.h>
#include <iostream>
#include <fstream>

using namespace std;

wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

// See http://www.idrix.fr/Root/Samples/capi_pem.cpp for the basis of this
int main(int argc, char *argv[])
{
	// Open the certificate file
	ifstream certFile;
	certFile.open(argv[1], ios::in | ios::binary | ios::ate);
	if (!certFile.is_open()) {
		cout << "Unable to open cert file: " << argv[1] << endl;
		return 1;
	}

	// Read the certificate file into memory
	streampos size = certFile.tellg();
	char *memblock = new char[size];
	certFile.seekg(0, ios::beg);
	certFile.read(memblock, size);
	certFile.close();

	// Parse the certificate
	PCCERT_CONTEXT cert = CertCreateCertificateContext(
		X509_ASN_ENCODING,
		(BYTE *)memblock,
		size);
	if (cert == NULL) {
		cout << "Unable to create CertCreateCertificateContext: " << GetLastError() << " data: " << memblock << endl;
		return 2;
	}

	// Open the system store into which to add the certificate
	HCERTSTORE store = CertOpenSystemStore(NULL, convertCharArrayToLPCWSTR(argv[2]));
	if (store == NULL) {
		cout << "Unable to open ROOT cert store: " << GetLastError() << endl;
		return 3;
	}
	
	// Add the certificate
	CRYPTUI_WIZ_IMPORT_SRC_INFO importSrc;
	memset(&importSrc, 0, sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO));
	importSrc.dwSize = sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO);
	importSrc.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_CONTEXT;
	importSrc.pCertContext = cert;
	importSrc.dwFlags = CRYPT_EXPORTABLE | CRYPT_USER_KEYSET;

	if (CryptUIWizImport(
		CRYPTUI_WIZ_NO_UI,
		NULL,
		NULL,
		&importSrc,
		store
		) == 0)
	{
		cout << "CryptUIWizImport error: " << GetLastError() << endl;
		return 1;
	}
	else {
		return 0;
	}
}

