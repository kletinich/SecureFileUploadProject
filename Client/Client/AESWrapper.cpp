#include "AESWrapper.h"

AESWrapper::AESWrapper(const unsigned char* key, unsigned int size)
{
	if (size != DEFAULT_KEYLENGTH)
		throw length_error("key length must be 32 bytes");
	memcpy_s(this->_key, DEFAULT_KEYLENGTH, key, size);
}

const unsigned char* AESWrapper::getKey() const
{
	return this->_key;
}

string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

	AES::Encryption aesEncryption(this->_key, DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	string cipher;
	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}

string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	

	AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	string decrypted;
	StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
