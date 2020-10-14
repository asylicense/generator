# include "LicenseClass.h"

# define LICENSE_INI_FILE		L"License.ini"
# define TEMPLATE_LIC_FILE		L"TemplateLic.key"
# define CERT_STORE_NAME		L"TrustedPublisher"
# define CERT_SERIAL_LEN		16

//# define MAX_PATH_LEN			256

# define CERT_NAME_PRE			L"CN = "
# define VALID_TIME_INDEX_LEN	2
# define LIC_SIG_INDEX_LEN		2

// Not together because of endian-ness
# define LIC_I_VALID_TIME_GAP	12

# define LIC_N_OFST_I			3

# define MAX_PATH_LEN			256

LicenseClass::LicenseClass(LPWSTR szLicPath)
{
	LPWSTR szIPath = new WCHAR[MAX_PATH_LEN];
	GetCurrentDirectory(MAX_PATH_LEN, szIPath);
	SetCurrentDirectory(szLicPath);

	szCertStore = CERT_STORE_NAME;
	ReadLic();

	ConfigClass Config(LICENSE_INI_FILE);
	{
	UINT lA = (sizeof CERT_NAME_PRE)/(sizeof WCHAR);
	UINT lB = Config.GetTokenLen()+1;
	szCompanyID = new WCHAR[lA+lB];
	wcscpy_s(szCompanyID, lA+lB, CERT_NAME_PRE);
	LPWSTR szTmp = szCompanyID+lA-1;
	Config.GetString(szTmp, lB);
	}
	{
	UINT l = Config.GetTokenLen();
	if(l != CERT_SERIAL_LEN*2)
		exit(-434554);
	arSerialNumber = new BYTE[l];
	Config.GetHex(arSerialNumber, l);
	}
	{
	UINT l = Config.GetTokenLen()+1;
	szLic = new WCHAR[l];
	Config.GetString(szLic, l);
	}
	arOfst = new UINT[LIC_N_OFST_I];
	{
	UINT l = Config.GetTokenLen();
	if(l > 2*sizeof UINT)
		exit(-798735630);
	arOfst[LIC_I_VALID_TIME_L] = 0;
	Config.GetHex((LPBYTE) &(arOfst[LIC_I_VALID_TIME_L]), 2*sizeof UINT);
	}
	arOfst[LIC_I_VALID_TIME_H] = arOfst[LIC_I_VALID_TIME_L]+LIC_I_VALID_TIME_GAP;
	{
	UINT l = Config.GetTokenLen();
	if(l > 2*sizeof UINT)
		exit(-688985657);
	arOfst[LIC_I_SIGNATURE] = 0;
	Config.GetHex((LPBYTE) &(arOfst[LIC_I_SIGNATURE]), 2*sizeof UINT);
	}
	SetCurrentDirectory(szIPath);
}

LPWSTR LicenseClass::CertStore()
{
	return szCertStore;
}

LPWSTR LicenseClass::CompanyID()
{
	return szCompanyID;
}

LPBYTE LicenseClass::SerialNumber()
{
	return arSerialNumber;
}

VOID LicenseClass::Insert(UINT iOfst, LPBYTE arHex, UINT len)
{
	if((iOfst+len) >= lBBuffer)
		exit(-5342643);
	LPWSTR hexBuffer = new WCHAR[len*2+2];
	HexStringW(hexBuffer, arHex, len);
	for(UINT i = 0, j = arOfst[iOfst], k = 1; i < len*2; i++, j++, k++)
	{
		if(k%3 == 0)
			i--;
		else
			Buffer[j] = hexBuffer[i];
	}
	delete hexBuffer;
}

VOID LicenseClass::ReadLic()
{
	FilesClass::ReadX((LPBYTE&)Buffer, lBBuffer, TEMPLATE_LIC_FILE);
}

VOID LicenseClass::WriteLic()
{
	FilesClass::WriteX((LPBYTE)Buffer, lBBuffer, szLic);
}
