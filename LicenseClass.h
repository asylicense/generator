# include <Windows.h>

# include "..\\Utilities\\Config\\ConfigClass.h"
# include "..\\Utilities\\Files\\FilesClass.h"

# define LIC_I_VALID_TIME_L		0
# define LIC_I_VALID_TIME_H		1

# define LIC_I_SIGNATURE		2

class LicenseClass
{
private:
	LPWSTR szCertStore;
	LPWSTR szCompanyID;
	LPBYTE arSerialNumber;
	LPWSTR szTemplateLic;
	LPWSTR szLic;
	UINT* arOfst;
	LPWSTR Buffer;
	UINT lBBuffer;
public:
	LicenseClass(LPWSTR szLicPath);
	LPWSTR CertStore();
	LPWSTR CompanyID();
	LPBYTE SerialNumber();

	VOID Insert(UINT iOfst, LPBYTE arHex, UINT len);

	VOID ReadLic(); // Read Template Lic
	VOID WriteLic();// Write Generated Lic
};
