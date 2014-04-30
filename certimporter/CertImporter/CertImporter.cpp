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
#include <iostream>
#include <fstream>

using namespace std;

const int STR_BUF_SZ = 4096;

wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
	wchar_t* wString = new wchar_t[STR_BUF_SZ];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, STR_BUF_SZ);
	return wString;
}

// See http://msdn.microsoft.com/en-us/library/windows/desktop/aa382363(v=vs.85).aspx
int checkExists(HCERTSTORE store, char *argv[]) {
	LPCWSTR expectedName = convertCharArrayToLPCWSTR(argv[3]);
	PCCERT_CONTEXT cert = CertFindCertificateInStore(
		store,
		X509_ASN_ENCODING,
		0,                
		CERT_FIND_SUBJECT_STR,
		expectedName,
		NULL);
	if (cert) {
		return 0;
	}
	else {
		cout << "No certificate was found with common name " << argv[3];
		return 2;
	}
}

// See http://www.idrix.fr/Root/Samples/capi_pem.cpp
// See http://msdn.microsoft.com/en-us/library/windows/desktop/aa382037(v=vs.85).aspx
// See http://blogs.msdn.com/b/alejacma/archive/2008/01/31/how-to-import-a-certificate-without-user-interaction-c-c.aspx
int addCert(HCERTSTORE store, char *argv[]) {
	// Open the certificate file
	char *certFileName = argv[3];
	ifstream certFile;
	certFile.open(certFileName, ios::in | ios::binary | ios::ate);
	if (!certFile.is_open()) {
		cout << "Unable to open cert file: " << certFileName << endl;
		return 2;
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
		return 3;
	}

	if (CertAddCertificateContextToStore(
		store,
		cert,
		CERT_STORE_ADD_REPLACE_EXISTING,
		NULL
		) == 0)
	{
		cout << "CertAddCertificateContextToStore error: " << GetLastError() << endl;
		return 4;
	}
	else {
		return 0;
	}
}
// See http://www.idrix.fr/Root/Samples/capi_pem.cpp for the basis of this
int main(int argc, char *argv[])
{
	LPCWSTR storeName = convertCharArrayToLPCWSTR(argv[2]);
	// Open the system store into which to add the certificate
	// See https://groups.google.com/forum/#!topic/microsoft.public.dotnet.security/iIkP0mkf5f4
	HCERTSTORE store = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		CERT_SYSTEM_STORE_LOCAL_MACHINE,
		storeName);
	if (store == NULL) {
		cout << "Unable to open " << argv[2] << " cert store: " << GetLastError() << endl;
		return 1;
	}

	char *action = argv[1];
	if (strncmp(action, "find", 4) == 0)
	{
		return checkExists(store, argv);
	}
	else
	{
		return addCert(store, argv);
	}
}



