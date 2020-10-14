# include "Generator.h"

# define PATH_SEPARATOR			L"\\"
# define LICENSE_STORE			L"Licenses"

# define MAX_BUFFER_LEN			1000

# define VALIDITY_DATE_INI		L"Validity Date.ini"
# define HASH_LEN				16

# define N_ARGS					2

# define MAX_PATH_LEN			256

# define MD5_HASH_LEN			16

INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, INT nShowCmd)
{
	INT nArgs;
	LPWSTR * szArgs;
	szArgs = CommandLineToArgvW(lpCmdLine, &nArgs);
	if(nArgs != N_ARGS)
		exit(-0xA1);

	LPWSTR szLicPath = new WCHAR[MAX_PATH_LEN];
	GetModuleFileName(NULL, szLicPath, MAX_PATH_LEN);
	FilesClass::GetFilePath(szLicPath);

	wcscat_s(szLicPath, MAX_PATH_LEN, PATH_SEPARATOR LICENSE_STORE PATH_SEPARATOR);
	wcscat_s(szLicPath, MAX_PATH_LEN, szArgs[0]);
	LicenseClass License(szLicPath);

	LPBYTE hashVal;
	hashVal = new BYTE[HASH_LEN];
	HexArrayW(hashVal, szArgs[1], HASH_LEN*2);

	FILETIME ftVTime;
	SYSTEMTIME stVTime;
	GetVTime(stVTime);
	SystemTimeToFileTime(&stVTime, &ftVTime);
	StampHash(hashVal, MD5_HASH_LEN, (LPBYTE) &ftVTime, sizeof FILETIME);

	LPBYTE pbSignature = NULL;
	DWORD dwSigLen = 0;
	HashSignClass HashSign(License.CertStore(), License.CompanyID(), License.SerialNumber());
	HashSign.GenSignature(hashVal, pbSignature, dwSigLen);
	License.Insert(LIC_I_VALID_TIME_L, (LPBYTE)&ftVTime.dwLowDateTime, sizeof UINT);
	License.Insert(LIC_I_VALID_TIME_H, (LPBYTE)&ftVTime.dwHighDateTime, sizeof UINT);
	License.Insert(LIC_I_SIGNATURE, pbSignature, dwSigLen);
	License.WriteLic();

	return 0;
}

VOID GetVTime(SYSTEMTIME& stVTime)
{
	ConfigClass Config(VALIDITY_DATE_INI);
	stVTime.wYear = Config.GetInt();
	stVTime.wMonth = Config.GetInt();
	stVTime.wDay = Config.GetInt();
	//stVTime.wDayOfWeek = Config.GetInt();
	stVTime.wHour = Config.GetInt();
	stVTime.wMinute = Config.GetInt();
	stVTime.wSecond = Config.GetInt();
	stVTime.wMilliseconds = Config.GetInt();
}
