# include <Windows.h>
# include <WinCrypt.h>
# pragma comment(lib, "Crypt32.lib")

# define MESSAGE_BOX_TITLE		L"Generator"

# define ERROR_S_STR_TO_NAME	L"Str to name error"
# define ERROR_S_STR_ALLOC		L"Str mem alloc fail"
# define ERROR_S_STR_TO_NAME_F	L"Str to name error final"
# define ERROR_S_CERT_NF		L"Cert Not Found"
# define ERROR_S_PRIVATE_KEY_NF	L"Private Key Not Found"
# define ERROR_S_CREATE_HASH	L"Error during Create Hash"
# define ERROR_S_SET_HASH		L"Error during Set Hash"
# define ERROR_S_STAMP_HASH		L"Error during Stamp Hash"
# define ERROR_S_SIGNATURE_LEN	L"Error during CryptSignHash"
# define ERROR_S_OUT_OF_MEM		L"Out of memory"
# define ERROR_S_CRYPT_SIGNHASH	L"Error during CryptSignHash"

# define SIZE_PUBLICKEY_BLOB	148
# define CERT_SERIAL_LEN		16

class HashSignClass
{
private:
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;

public:
	HashSignClass(LPWSTR szCertStore, LPWSTR szCompanyID, LPBYTE arSerialNumber);
	VOID GenSignature(LPBYTE hashVal, LPBYTE& pbSignature, DWORD& dwSigLen);
};
