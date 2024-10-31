#include "RSAWrapper.h"

RSAPublicWrapper::RSAPublicWrapper(const string& key)
{
	StringSource ss(key, true);
	this->_publicKey.Load(ss);
}

RSAPrivateWrapper::RSAPrivateWrapper()
{
	this->_privateKey.Initialize(this->_rng, BITS);
}

RSAPrivateWrapper::RSAPrivateWrapper(const std::string& key)
{
	StringSource ss(key, true);
	this->_privateKey.Load(ss);
}

string RSAPrivateWrapper::getPublicKey() const
{
	RSAFunction publicKey(_privateKey);
	string key;
	StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

string RSAPrivateWrapper::getPrivateKey() const
{
	string key;
	StringSink ss(key);
	this->_privateKey.Save(ss);
	return key;
}

string RSAPrivateWrapper::decrypt(const string& cipher)
{
	string decrypted;

	try {
		RSAES_OAEP_SHA_Decryptor d(this->_privateKey);
		StringSource ss_cipher(cipher, true,
			new PK_DecryptorFilter(this->_rng, d,
				new StringSink(decrypted)));
	}
	catch (const CryptoPP::Exception& ex)
	{
		cerr << ex.what() << endl;
	}

	return decrypted;
}