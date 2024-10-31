#include "UUIDHandler.h"

// convert UUID from hex representation to ascii representation
char* UUIDHandler::UUIDToAscii(const unsigned char* uuidBytes)
{
	stringstream ss;
	string s;

	ss << hex << setfill('0');
	for (int i = 0; i < 16; ++i) {
		ss << setw(2) << static_cast<unsigned int>(uuidBytes[i]);
	}
	s = ss.str();
	char* uuidAscii = new char[s.length() + 1];
	strcpy(uuidAscii, s.c_str());
	return uuidAscii;
}

// convert UUID from ascii representation to hex representation 
char* UUIDHandler::asciiToUUID(const char* uuidAscii)
{
	char* uuidBytes = new char[16];
	for (int i = 0; i < 16; ++i) {
		string byteString = string(uuidAscii + 2 * i, 2);
		uuidBytes[i] = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
	}

	return uuidBytes;
}