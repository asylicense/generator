# include "HashSignClass.h"

HashSignClass::HashSignClass(LPWSTR szCertStore, LPWSTR szCompanyID, LPBYTE arSerialNumber)
{
	HCERTSTORE hCertS;
	if(!(hCertS = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_OPEN_EXISTING_FLAG |CERT_STORE_READONLY_FLAG, szCertStore)))
		exit(-5435435);
	CERT_INFO certInfo;
	memset((void *)&certInfo, 0, sizeof(CERT_INFO));
	CERT_NAME_BLOB companyID;
	if(!CertStrToName(
		X509_ASN_ENCODING,
		szCompanyID,
		CERT_OID_NAME_STR,
		NULL,
		NULL,
		&companyID.cbData,
		NULL))
		MessageBox(NULL, ERROR_S_STR_TO_NAME, MESSAGE_BOX_TITLE, MB_OK);

	if(!(companyID.pbData = new BYTE[companyID.cbData]))
		MessageBox(NULL, ERROR_S_STR_ALLOC, MESSAGE_BOX_TITLE, MB_OK);

	if(!CertStrToName(
		X509_ASN_ENCODING,
		szCompanyID,
		CERT_OID_NAME_STR,
		NULL,
		companyID.pbData,
		&companyID.cbData,
		NULL))
		MessageBox(NULL, ERROR_S_STR_TO_NAME_F, MESSAGE_BOX_TITLE, MB_OK);
	certInfo.Issuer = companyID;
	CRYPT_INTEGER_BLOB serialNumber;
	serialNumber.cbData = CERT_SERIAL_LEN;
	serialNumber.pbData = arSerialNumber;
	certInfo.SerialNumber = serialNumber;

	PCCERT_CONTEXT certContext;
	certContext = CertGetSubjectCertificateFromStore(hCertS, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, &certInfo);
	if(GetLastError() == CRYPT_E_NOT_FOUND)
		MessageBox(NULL, ERROR_S_CERT_NF, MESSAGE_BOX_TITLE, MB_OK);

	// Public Key blob in: pbKey
	DWORD dwKeySpec;
	PBYTE pbPKEY = NULL;
	DWORD iPKEYSize;
	CryptDecodeObjectEx((PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
		RSA_CSP_PUBLICKEYBLOB,
		certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
		certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
		CRYPT_ENCODE_ALLOC_FLAG,
		NULL,
		&pbPKEY,
		&iPKEYSize);

	CryptAcquireCertificatePrivateKey(certContext, 0, NULL, &hProv, &dwKeySpec, NULL);
	if(CRYPT_E_NO_KEY_PROPERTY == GetLastError())
		MessageBox(NULL, ERROR_S_PRIVATE_KEY_NF, MESSAGE_BOX_TITLE, MB_OK);

	if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		MessageBox(NULL, ERROR_S_CREATE_HASH, MESSAGE_BOX_TITLE, MB_OK);
}

VOID HashSignClass::GenSignature(LPBYTE hashVal, LPBYTE& pbSignature, DWORD& dwSigLen)
{
	if(!CryptSetHashParam(hHash, HP_HASHVAL, hashVal, 0))
		MessageBox(NULL, ERROR_S_SET_HASH, MESSAGE_BOX_TITLE, MB_OK);

	dwSigLen= 0;
	if(!CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		NULL, 
		0, 
		NULL, 
		&dwSigLen)) 
		MessageBox(NULL, ERROR_S_SIGNATURE_LEN, MESSAGE_BOX_TITLE, MB_OK);

	if(!(pbSignature = new BYTE[dwSigLen]))
		MessageBox(NULL, ERROR_S_OUT_OF_MEM, MESSAGE_BOX_TITLE, MB_OK);

	if(!CryptSignHash(
		hHash, 
		AT_SIGNATURE, 
		NULL, 
		0, 
		pbSignature, 
		&dwSigLen)) 
		MessageBox(NULL, ERROR_S_CRYPT_SIGNHASH, MESSAGE_BOX_TITLE, MB_OK);
}
