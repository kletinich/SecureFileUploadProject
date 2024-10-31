#pragma once

#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

class UUIDHandler
{
public:
	static char* UUIDToAscii(const unsigned char* uuidBytes);
	static char* asciiToUUID(const char* uuidAscii);
};
