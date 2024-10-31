#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include "AESWrapper.h"
#include "CodesAndConstants.h"

#pragma once
using namespace std;

class FileHandler
{
public:
	static vector<string> readFromTransferFile();
	static string readFromPrivKey();
	static vector<string> readFromMeFile();
	static unsigned int createMeFile(const char* clientName, const char* clientUUID, const char* privateKey);
	static unsigned int createPrivKeyFile(const char* privateKey);
	static vector<unsigned int> getDataForSentFile(const string fileName, const unsigned int headerSize, AESWrapper* aesWrapper);
};