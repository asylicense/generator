Generator
===
License file generator

- Commandline argument:
		- License path location containing License.ini
		- Device Id - MD5 hash
- Working directory:
		- License directory containing ValidityDate.ini

The generated file is a registry file that contains the license key

Requisites:
- Certificate installed in "Trusted publisher" that has private key required to generate the license key

Public key:
- Generates public key blob required by the Registration dll  
// Public Key blob in: HashSignClass - pbKey
