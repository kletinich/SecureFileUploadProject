#pragma once

#include <string>
#include <base64.h>

using namespace std;
using namespace CryptoPP;

class Base64Wrapper
{
public:
	static string encode(const string& str);
	static string decode(const string& str);
};
