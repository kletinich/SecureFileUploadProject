#pragma once

#include <osrng.h>
#include <rsa.h>

#include <string>

using namespace std;
using namespace CryptoPP;

class RSAPublicWrapper
{
public:
	static const unsigned int KEYSIZE = 160;
	static const unsigned int BITS = 1024;

private:
	AutoSeededRandomPool _rng;
	RSA::PublicKey _publicKey;

public:
	RSAPublicWrapper(const string& key);
};

class RSAPrivateWrapper
{
public:
	static const unsigned int BITS = 1024;

private:
	AutoSeededRandomPool _rng;
	RSA::PrivateKey _privateKey;

public:
	RSAPrivateWrapper();
	RSAPrivateWrapper(const std::string& key);

	string getPublicKey() const;
	string getPrivateKey() const;

	string decrypt(const string& cipher);
};