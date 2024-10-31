#include "FileHandler.h"

// Read and return data from transfer.info file
vector<string> FileHandler::readFromTransferFile()
{
	ifstream transferFile;
	string line = "";
	string temp = "";
	int tokenLength = 0;
	vector<string> lines;

	transferFile.open("transfer.info");

	if (transferFile.is_open())
	{
		while (getline(transferFile, line))
		{
			lines.push_back(line);
		}

		transferFile.close();
	}

	else
	{
		cerr << "Can't open transfer.info. Terminating the program\n";
	}
	
	return lines;
}

// Read and return data from priv.key file
string FileHandler::readFromPrivKey()
{
	ifstream privKeyFile;
	string privateKey = "";
	string line;

	privKeyFile.open("priv.key");

	if (privKeyFile.is_open())
	{
		while (getline(privKeyFile, line))
		{
			privateKey += line;
		}

		privKeyFile.close();

		return privateKey;
	}

	cerr << "Can't open priv.key file. Terminating the program\n";
	exit(FAILURE);
}

// Read and return data from me.info file
vector<string> FileHandler::readFromMeFile()
{
	ifstream meFile;
	string line;
	vector<string> lines;

	meFile.open("me.info");

	if (meFile.is_open())
	{
		getline(meFile, line);
		lines.push_back(line);
		getline(meFile, line);
		lines.push_back(line);

		meFile.close();
	}

	else
	{
		cerr << "Can't open me.info. Terminating the program\n";
	}

	return lines;
}

// Create me.info file and write the client name, UUID and the private key to it
unsigned int FileHandler::createMeFile(const char* clientName, const char* clientUUID, const char* privateKey)
{
	ofstream meFile("me.info");

	if (meFile.is_open())
	{
		meFile << clientName << "\n";
		meFile << clientUUID << "\n";
		meFile << privateKey << "\n";
		cout << "Me.info created successfuly\n";
	}

	else
	{
		cerr << "Error while writing to me.info\n";
		return FAILURE;
	}

	meFile.close();
	return SUCCESS;
}

// Create priv.key file and write the private key to it
unsigned int FileHandler::createPrivKeyFile(const char* privateKey)
{
	ofstream privKeyFile("priv.key");

	if (privKeyFile.is_open())
	{
		privKeyFile << privateKey << "\n";
		cout << "priv.key created successfuly\n";
	}

	else
	{
		cerr << "Error while writing to priv.key\n";
		return FAILURE;
	}

	privKeyFile.close();
	return SUCCESS;
}

// calculate encrypted file length, original file length, number of chunks to be sent to the server
vector<unsigned int> FileHandler::getDataForSentFile(const string fileName, const unsigned int headerSize, AESWrapper* aesWrapper)
{
	ifstream file;
	char buffer[BUFFER_SIZE] = { 0 };
	string encryptedData = "";
	int fileDataLength = 0;
	int encryptedDataLength = 0;
	int packetsNeeded = 0;
	int encryptedDataTotalLength = 0;

	vector<unsigned int> data;

	file.open(fileName);

	if (file.is_open())
	{
		file.seekg(0, ios::end);
		fileDataLength = file.tellg();
		file.seekg(0, ios::beg);

		if (fileDataLength == 0)
		{
			cerr << "File is empty. No need for encryption\n";
			return data;
		}
	
		while (!file.eof())
		{
			file.read(buffer, BUFFER_SIZE); 
			streamsize bytesRead = file.gcount();

			encryptedData = aesWrapper->encrypt(buffer, bytesRead);
			encryptedDataLength = encryptedData.length();
			
			encryptedDataTotalLength += encryptedDataLength;

			while(encryptedDataLength != 0)
			{
				packetsNeeded++;
				encryptedDataLength /= (BUFFER_SIZE - headerSize);
			}
		}

		data.push_back(packetsNeeded);
		data.push_back(fileDataLength);
		data.push_back(encryptedDataTotalLength);

		file.close();
	}

	else
	{
		cerr << "Can't open " << fileName << endl;
	}

	return data;
}
