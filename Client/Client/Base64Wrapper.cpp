#include "Base64Wrapper.h"


string Base64Wrapper::encode(const string& str)
{
	string encoded;
	StringSource ss(str, true,
		new Base64Encoder(
			new StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

string Base64Wrapper::decode(const string& str)
{
	string decoded;
	StringSource ss(str, true,
		new Base64Decoder(
			new StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}
