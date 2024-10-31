#pragma once

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <stdexcept>
#include <immintrin.h>

using namespace std;
using namespace CryptoPP;

class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 32;

private:
	unsigned char _key[DEFAULT_KEYLENGTH];

public:
	AESWrapper(const unsigned char* key, unsigned int size);

	const unsigned char* getKey() const;

	string encrypt(const char* plain, unsigned int length);
	string decrypt(const char* cipher, unsigned int length);
};
