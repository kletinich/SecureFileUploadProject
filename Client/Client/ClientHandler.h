#pragma once

#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <WS2tcpip.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

#include "CodesAndConstants.h"
#include "FileHandler.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "UUIDHandler.h"
#include "Cksum.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(suppress : 6387)
#pragma warning(suppress : 6308)

using namespace std;

class ClientHandler
{
private:
	string clientName;
	string serverIP;
	unsigned int serverPort;
	string fileFromTransfer;
	string UUIDAscii;

	uint8_t clientVersion;

	SOCKET clientFd;
	
	AESWrapper* aesWrapper;

public:
	ClientHandler();
	~ClientHandler();

	unsigned int startClient();

private:
	unsigned int setSocket();
	unsigned int connectedToServer();

	unsigned int registerProcedure();
	unsigned int reconnectionProcedure();
	unsigned int sendFileProcedure(const string fileName);

	unsigned int connectionRequests(const unsigned int requestCode);
	char* packHeader(const unsigned int requestCode);

	unsigned int receiveResponse();
	vector<unsigned int> readHeader(const char* buffer);

	unsigned int registeredToServer(const uint32_t payloadSize, const char* buffer, unsigned int offset);
	string generateRSAKeys();
	unsigned int receivedAESKey(const uint32_t payloadSize, const char* buffer, unsigned int offset);


	unsigned int sendFileToServer(string fileName);
	unsigned int receivedChecksum(const uint32_t payloadSize, const char* buffer, unsigned int offset);
	unsigned int checksumStatus(const int requestCode, string fileName);
};