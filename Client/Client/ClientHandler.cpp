#include "ClientHandler.h"

ClientHandler::ClientHandler()
{
	vector<string> transferMeLines;
	int tokenLength = 0;

	this->clientVersion = 17;

	transferMeLines = FileHandler::readFromTransferFile();

	// Couldn't read file content. Exiting
	if (transferMeLines.empty())
		exit(FAILURE);

	this->fileFromTransfer.assign(transferMeLines.back());
	transferMeLines.pop_back();

	this->clientName.assign(transferMeLines.back());
	transferMeLines.pop_back();

	tokenLength = strcspn(transferMeLines.back().c_str(), ":");
	this->serverIP.assign(transferMeLines.back().c_str(), tokenLength);

	tokenLength = strcspn(transferMeLines.back().c_str() + tokenLength + 1, "");
	this->serverPort = atoi(transferMeLines.back().c_str() + this->serverIP.length() + 1);

	this->clientFd = 0;
	this->aesWrapper = NULL;
	
}

ClientHandler::~ClientHandler()
{
	if (this->aesWrapper != NULL)
	{
		delete(this->aesWrapper);
	}

	cout << "Client deleted\n";
}

/* Start the communication proccess with the server:
****************************************************
*	1. Set the socket to the server				   *
*	2. Connected to the server					   *
***************************************************/
unsigned int ClientHandler::startClient()
{
	if (setSocket() == FAILURE)
		return FAILURE;

	if (connectedToServer() == FAILURE)
		return FAILURE;

	return SUCCESS;
}

/* Set the socket to the server:
********************************
*	1. new socket			   *
*	2. connect				   * 
*******************************/
unsigned int ClientHandler::setSocket()
{
	WSADATA wsData;
	if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0)
	{
		cerr << "Error: WSAStartup failed.\n";
		return FAILURE;
	}

	this->clientFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (this->clientFd == INVALID_SOCKET)
	{
		cerr << "Error: Unable to create socket.\n";
		WSACleanup();
		return FAILURE;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(this->serverPort);
	inet_pton(AF_INET, this->serverIP.c_str(), &serverAddr.sin_addr);

	if (connect(this->clientFd, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR)
	{
		cout << "Unable to connect to server through port " << this->serverPort << ". Trying port " << DEFAULT_SERVER_PORT << endl;

		serverAddr.sin_port = htons(DEFAULT_SERVER_PORT);

		if (connect(this->clientFd, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR)
		{
			cerr << "Error: Can't connect to server through port " << DEFAULT_SERVER_PORT << endl;
			closesocket(this->clientFd);
			WSACleanup();
			return FAILURE;
		}
	}

	return SUCCESS;
}

/* Procedure of communication with the server:
*********************************************
*	1. register or reconnect to server		*
*	2. send file to server					*		
********************************************/
unsigned int ClientHandler::connectedToServer()
{
	ifstream meFile;
	unsigned int status = 0;

	meFile.open("me.info");

	// me.info doesn't exists. register to server
	if(not meFile.is_open())
		status = registerProcedure();

	// me.info exists. reconnect to server
	else
		status = reconnectionProcedure();

	// communication with the server procedure
	if(status == SUCCESS)
		sendFileProcedure("test.txt");

	return SUCCESS;
}

/*Procedure of registering to server:
*************************************
*	1. send register request		*
*	2. receive UUID from server		*
*	3. send public key				*
*	4. receive encrypted aes key	*
************************************/								
unsigned int ClientHandler::registerProcedure()
{
	unsigned int responseStatus = 0;

	for (int tries = 1; tries <= 4; tries++)
	{
		cout << "Attempt to register to the server" << endl;

		// register to server
		if (connectionRequests(REGISTER_REQUEST_CODE) == FAILURE)
			return FAILURE;

		// receive UUID from server
		responseStatus = receiveResponse();

		if (responseStatus == SUCCESS)
		{
			cout << "Attempt to register to the server was successfull" << endl;
			break;
		}

		else if (responseStatus != SUCCESS && tries == 4)
		{
			cout << "4th attemt to register to the server failed. Aborting" << endl;
			return responseStatus;
		}
	}

	for (int tries = 1; tries <= 4; tries++)
	{
		cout << "Sending public key to the server" << endl;

		// send public key to server
		if (connectionRequests(PUBLIC_KEY_SEND_CODE) == FAILURE)
			return FAILURE;

		// receive encrypted aes key from server
		responseStatus = receiveResponse();

		if (responseStatus == SUCCESS)
		{
			cout << "Received encrypted AES key from the server" << endl;
			break;
		}

		else if (responseStatus != SUCCESS && tries == 4)
		{
			cout << "4th attemt to receive encrypted AES key failed. Aborting" << endl;
			return responseStatus;
		}
	}

	return SUCCESS;
}

/* Procedure of reconnection to server:
***************************************
*	1. send reconnection request	  *
*	2. receive encrypted aes key	  *
**************************************/
unsigned int ClientHandler::reconnectionProcedure()
{
	vector<string> lines = FileHandler::readFromMeFile();
	unsigned int responseStatus = 0;

	// Can't read file or file is empty
	if (lines.empty())
		return FAILURE;

	this->UUIDAscii = lines.back();
	lines.pop_back();

	this->clientName = lines.back();
	lines.pop_back();

	for (int tries = 1; tries <= 4; tries++)
	{
		cout << "Attempt to reconnect to the server" << endl;

		if (connectionRequests(RECONNECTION_REQUEST_CODE) == FAILURE)
			return FAILURE;

		responseStatus = receiveResponse();

		if (responseStatus == SUCCESS)
		{
			cout << "Attempt to reconnect to the server was successfull. Received encrypted AES key" << endl;
			break;
		}

		else if (responseStatus != SUCCESS && tries == 4)
		{
			cout << "4th attemt to reconnect to the server failed. Aborting" << endl;
			return responseStatus;
		}
	}

	return SUCCESS;
}

/* Procedure of sending file to server:
***************************************
*	1. send encrypted file to server  *
*	2. receive checksum				  *
*	3. compare checksums		      *
*	4. respond according to			  *
*	   the comparison				  *
**************************************/
unsigned int ClientHandler::sendFileProcedure(const string fileName)
{
	unsigned int responseStatus = 0;

	for (int tries = 1; tries <= 4; tries++)
	{
		cout << "Attempt to send encrypted file to server" << endl;

		if (sendFileToServer(fileName) == FAILURE)
			return FAILURE;

		responseStatus = receiveResponse();
		
		// checksum on both sides match
		if (responseStatus == SUCCESS)
		{
			cout << "CRC confirmd successfully" << endl;
			checksumStatus(CORRECT_CRC_CODE, fileName);
			receiveResponse();

			break;
		}

		// checksums don't match. Need to send encrypted file again
		else if (responseStatus != SUCCESS && tries < 4)
		{
			cout << "Failed to confirm CRC" << endl;
			checksumStatus(INCORRECT_CRC_SEND_AGAIN_CODE, fileName);
		}

		// checksums don't match the 4th time. Sending abort message
		else if (responseStatus != SUCCESS && tries == 4)
		{
			cerr << "Failed to confirm CRC for the 4th time. Aborting" << endl;
			checksumStatus(INCORRECT_CRC_ABORT_CODE, fileName);
			receiveResponse();

			return FAILURE;
		}
	}
	
	return SUCCESS;
}

/* Pack one request and send it to the server:
**********************************************
*	1. register request						 *
*	2. public key send request				 *
*	3. reconnection request					 *
*********************************************/
unsigned int ClientHandler::connectionRequests(const unsigned int requestCode)
{
	char* request = NULL;
	char* payload = NULL;
	string publicKeyStr = "";
	uint32_t payloadSize = 0;
	unsigned int offset = 0;

	// packs the header that will be sent to the server 
	request = packHeader(requestCode);

	offset = UUID_SIZE / 2 + sizeof(uint8_t) + sizeof(uint16_t);
		
	payloadSize = this->clientName.length() + 1;

	if (requestCode == PUBLIC_KEY_SEND_CODE)
	{
		publicKeyStr = generateRSAKeys();
		payloadSize += strlen(publicKeyStr.c_str());
	}

	payloadSize = htonl(payloadSize);
	memcpy(request + offset, &payloadSize, sizeof(uint32_t));
	offset += sizeof(uint32_t);
	payloadSize = htonl(payloadSize);

	payload = (char*)malloc(payloadSize);

	strncpy(payload, this->clientName.c_str(), this->clientName.length());
		
	if (requestCode == PUBLIC_KEY_SEND_CODE)
		strncpy(payload + this->clientName.length(), publicKeyStr.c_str(), publicKeyStr.length());

	request = (char*)realloc(request, offset + static_cast<size_t>(payloadSize));
	
	if(request == NULL)
	{ 
		cerr << "Can't allocate memory. Terminating\n";
		free(payload);
		return FAILURE;
	}
	

	memcpy(request + offset, payload, strlen(payload));

	send(this->clientFd, request, offset + payloadSize, 0);

	free(request);
	free(payload);

	return SUCCESS;
}

/* Pack the header of the request:
**********************************
*	1. UUID						 *
*	2. client version			 *
*	3. request code				 *
*********************************/
char* ClientHandler::packHeader(const unsigned int requestCode)
{
	char* requestHeader = (char*)malloc(UUID_SIZE / 2 + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t));
	uint16_t code = requestCode;
	int offset = 0;

	code = htons(requestCode);
	
	// add client id to the request message if the message is not a register request
	if (REGISTER_REQUEST_CODE != requestCode)
	{	
		memcpy(requestHeader, UUIDHandler::asciiToUUID(this->UUIDAscii.c_str()), UUID_SIZE/2);
	}

	offset += UUID_SIZE / 2;

	memcpy(requestHeader + offset, &(this->clientVersion), sizeof(uint8_t));
	offset += sizeof(uint8_t);

	memcpy(requestHeader + offset, &code, sizeof(uint16_t));
	offset += sizeof(uint16_t);

	return requestHeader;
}

/* Receive response from the server:
************************************
*	1. General error 			   *
*	2. Register success            *
*	3. Register failure            *
*	4. Reconnection success and    *
*	   receive AES key             *
*	5. Reconnection declined	   *
*   6. Server received file and    *
*	   sent checksum value	       *
***********************************/
unsigned int ClientHandler::receiveResponse()
{
	vector<unsigned int> header;
	uint8_t serverVersion;
	uint16_t serverCode;
	uint32_t payloadSize;

	string publicKey;

	char buffer[BUFFER_SIZE] = { 0 };
	unsigned int offset = 0;

	int bytesReceived;

	bytesReceived = recv(this->clientFd, buffer, BUFFER_SIZE, 0);

	if (bytesReceived <= 0)
	{
		cerr << "Connection closed by server\n";
		return FAILURE;
	}

	// read the header into a vector
	header = readHeader(buffer);

	serverVersion = header.back();
	header.pop_back();

	serverCode = header.back();
	header.pop_back();

	payloadSize = header.back();
	header.pop_back();

	offset = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t);

	// different responses from the server
	switch(serverCode)
	{
	// Received some general error from the server
	case(GENERAL_ERROR_CODE):
		cerr << "Error code " << serverCode << ": Can't register to the server\n";
		return GENERAL_ERROR_CODE;

	// Registered to server. Need to create RSA key pairs and send the server the public key
	case(REGISTER_SUCCESS_CODE):
		registeredToServer(payloadSize, buffer, offset);
		break;

	// Client already registered to server. Need to reconnect
	case(REGISTER_FAILURE_CODE):
		cerr << "Error code " << serverCode << ": Client already registered to server\n";
		reconnectionProcedure();
		break;

	// Received encrypted Aes key from server as a result of registering or reconnecting
	case(AES_SEND_CODE):
	case(RECONNECTION_SUCCESS_CODE):
		receivedAESKey(payloadSize, buffer, offset);
		break;

	// Can't reconnect. Need to register 
	case(RECONNECTION_DECLINED_CODE):
		cerr << "reconnection declined\n";
		registerProcedure();
		break;

	case(FILE_RECEIVED_SUCSSESSFULY_CODE):
		return (receivedChecksum(payloadSize, buffer, offset));
		break;

	case(ACCEPT_MESSAGE_THANKS_CODE):
		cout << "Disconnecting from server" << endl;
		break;
	}

	return SUCCESS;
}

/* Read and unpack the header of the response from the server:
*******************************
*	1. server version	      *								
*	2. server code		      *
*	3. payload size           *
******************************/
vector<unsigned int> ClientHandler::readHeader(const char* buffer)
{
	vector<unsigned int> header;
	uint8_t serverVersion;
	uint16_t serverCode;
	uint32_t payloadSize;
	unsigned int offset = 0;

	serverVersion = static_cast<uint8_t>(buffer[0]);
	offset += sizeof(uint8_t);

	memcpy(&serverCode, buffer + offset, sizeof(uint16_t));
	serverCode = ntohs(serverCode);
	offset += sizeof(uint16_t);

	memcpy(&payloadSize, buffer + offset, sizeof(uint32_t));
	payloadSize = ntohl(payloadSize);

	header.push_back(payloadSize);
	header.push_back(serverCode);
	header.push_back(serverVersion);

	return header;
}

/* received the UUID the server generated:
******************************************
*	1. read the UUID to a bytes string   *
*	2. translate the UUID to ascii       *
*****************************************/
unsigned int ClientHandler::registeredToServer(const uint32_t payloadSize, const char* buffer, unsigned int offset)
{
	string UUID;

	UUID.assign(buffer + offset, payloadSize);
	UUIDAscii.assign(UUIDHandler::UUIDToAscii(reinterpret_cast<const unsigned char*>(UUID.c_str())), UUID_SIZE);

	return SUCCESS;
}

/* Generate the RSA key pair for future usage:
**********************************************
*	1. generate private and public keys      *
*	2. create me.info file					 *
*	3. create priv.key file					 *
*********************************************/
string ClientHandler::generateRSAKeys()
{
	RSAPrivateWrapper privateWrapper;
	string publicKey = Base64Wrapper::encode(privateWrapper.getPublicKey());
	string privateKey = Base64Wrapper::encode(privateWrapper.getPrivateKey());
	FileHandler::createMeFile(this->clientName.c_str(), this->UUIDAscii.c_str(), privateKey.c_str());
	FileHandler::createPrivKeyFile(privateKey.c_str());
	return publicKey;
}

/* Received an encrypted AES key. Decrypt and save it:
******************************************************
*	1. decode the private key        				 *
*	2. decrypt the aes key							 *
*	3. save the aes key for future useage            *
*****************************************************/
unsigned int ClientHandler::receivedAESKey(const uint32_t payloadSize, const char* buffer, unsigned int offset)
{
	string UUID = "";
	string privateKey = "";
	string encryptedAESKey = "";

	unsigned char aesKey[AES_KEY_SIZE/8] = { 0 };

	UUID.assign(buffer + offset, UUID_SIZE/2);
	this->UUIDAscii.assign(UUIDHandler::UUIDToAscii(reinterpret_cast<const unsigned char*>(UUID.c_str())), UUID_SIZE);
	offset += UUID_SIZE/2;

	encryptedAESKey.assign(buffer + offset, AES_KEY_SIZE);

	privateKey = FileHandler::readFromPrivKey();
	RSAPrivateWrapper privateWrapper(Base64Wrapper::decode(privateKey));

	memcpy(aesKey, privateWrapper.decrypt(encryptedAESKey).c_str(), 16);
	this->aesWrapper = new AESWrapper(aesKey, AESWrapper::DEFAULT_KEYLENGTH);

	return SUCCESS;
}

/* Encrypt and send a given file to the server:
***********************************************
*	1. get number of chunks required to send  *
*	   the encrypted file                     *
*	2. encrypt a file chunk by chunk		  *
*	3. send the file chunk by chunk		      *
**********************************************/
unsigned int ClientHandler::sendFileToServer(string fileName)
{
	ifstream file; // file to encrypt and send to the server
	vector<unsigned int> data; // encrypted file length, original file length, number of packets needed to send
	char fileBuffer[BUFFER_SIZE] = { 0 }; // buffer to read file data to it
	char responseBuffer[BUFFER_SIZE] = { 0 }; // buffer to get response from server

	uint32_t encryptedFileTotalLength = 0; // length of file before encryption
	uint32_t originalFileTotalLength = 0; // length of file after encryption
	uint16_t currentPacketNumber = 1; // the current packet sent
	uint16_t totalNumOfPackets = 0; // total number of packets needed to be sent

	char* request = NULL; // the request to be sent to the server

	char* header = NULL; // the header of the request
	unsigned int headerOffset = 0; // offset for the header

	unsigned int maxEncryptedLengthForPacket = 0; // max length for encrypted data in one packet
	unsigned int encryptedDataOffset = 0; // offset for encryptedDataChunk
	string encryptedDataChunk = ""; // an encrypted chunk of data from the file
	string subEncryptedDataChunk = ""; // substring of the encrypted chunk of data
	unsigned int encryptedDataChunkLength = 0; // total length of the encrypted chunk
	unsigned int currentEncryptedChunkLength = 0; // a legal length that the encrypted chunk can be sent

	unsigned int payloadOffset = 0; // offset for the payload
	uint32_t payloadSize; // size of the payload part of the request
	char* payload = NULL; // the payload of the request

	file.open(fileName);

	if (file.is_open())
	{
		if (fileName.length() > FILE_NAME_MAX_LENGTH)
		{
			cerr << "File name is too long for handeling\n";
			file.close();
			return FAILURE;
		}

		data = FileHandler::getDataForSentFile(fileName, HEADER_SIZE, this->aesWrapper);

		if (data.empty())
			return FAILURE;

		encryptedFileTotalLength = data.back();
		data.pop_back();

		originalFileTotalLength = data.back();
		data.pop_back();

		totalNumOfPackets = data.back();
		data.pop_back();

		fileName.resize(FILE_NAME_MAX_LENGTH, '\0');

		header = packHeader(FILE_SEND_CODE);
		
		maxEncryptedLengthForPacket = BUFFER_SIZE - HEADER_SIZE - 3 * sizeof(uint32_t) - fileName.length() - 14;

		// sending the file packet by packet
		while (!file.eof())
		{
			encryptedDataOffset = 0;

			memset(fileBuffer, 0, BUFFER_SIZE);
			file.read(fileBuffer, BUFFER_SIZE);
			streamsize bytesRead = file.gcount();

			encryptedDataChunk = this->aesWrapper->encrypt(fileBuffer, bytesRead);
			encryptedDataChunkLength = encryptedDataChunk.length();

			while (encryptedDataChunkLength > 0)
			{
				headerOffset = UUID_SIZE / 2 + sizeof(uint8_t) + sizeof(uint16_t);
				payloadOffset = 0;

				// need to seperate encrypted message to more than 1 chunk
				if(encryptedDataChunkLength > maxEncryptedLengthForPacket)
				{
					currentEncryptedChunkLength = maxEncryptedLengthForPacket;
					encryptedDataChunkLength -= currentEncryptedChunkLength;
				}

				// the encrypted message length is enough for 1 chunk
				else
				{
					currentEncryptedChunkLength = encryptedDataChunkLength;
					encryptedDataChunkLength = 0;
				}

				subEncryptedDataChunk = encryptedDataChunk.substr(encryptedDataOffset, currentEncryptedChunkLength);

				// packing payload size to header
				payloadSize = sizeof(uint32_t) * 3 + fileName.length() + currentEncryptedChunkLength + 1;
				payloadSize = htonl(payloadSize);
				memcpy(header + headerOffset, &payloadSize, sizeof(uint32_t));
				payloadSize = htonl(payloadSize);
				headerOffset += sizeof(uint32_t);

				payload = (char*)malloc(sizeof(uint32_t) * 3 + fileName.length() + currentEncryptedChunkLength);
				
				// packing the encrypted file length to payload
				encryptedFileTotalLength = ntohl(encryptedFileTotalLength);
				memcpy(payload + payloadOffset, &encryptedFileTotalLength, sizeof(uint32_t));
				encryptedFileTotalLength = ntohl(encryptedFileTotalLength);
				payloadOffset += sizeof(uint32_t);

				// packing the original file length to payload
				originalFileTotalLength = ntohl(originalFileTotalLength);
				memcpy(payload + payloadOffset, &originalFileTotalLength, sizeof(uint32_t));
				originalFileTotalLength = ntohl(originalFileTotalLength);
				payloadOffset += sizeof(uint32_t);

				// packing the current packet number to payload
				currentPacketNumber = ntohs(currentPacketNumber);
				memcpy(payload + payloadOffset, &currentPacketNumber, sizeof(uint16_t));
				currentPacketNumber = ntohs(currentPacketNumber);
				currentPacketNumber++;
				payloadOffset += sizeof(uint16_t);

				// packing the total number of packets to payload
				totalNumOfPackets = ntohs(totalNumOfPackets);
				memcpy(payload + payloadOffset, &totalNumOfPackets, sizeof(uint16_t));
				totalNumOfPackets = ntohs(totalNumOfPackets);
				payloadOffset += sizeof(uint16_t);

				//packing the file name to payload
				memcpy(payload + payloadOffset, fileName.c_str(), fileName.length());
				payloadOffset += fileName.length();

				// packing the encrypted chunk to payload
				memcpy(payload + payloadOffset, subEncryptedDataChunk.c_str(), subEncryptedDataChunk.length());
				payloadOffset += subEncryptedDataChunk.length();

				request = (char*)malloc(headerOffset + payloadOffset);
			
				// pack the header and the payload to the request
				memcpy(request, header, headerOffset);
				memcpy(request + headerOffset, payload, payloadOffset);

				send(this->clientFd, request, headerOffset + payloadOffset, 0);

				if (currentPacketNumber < totalNumOfPackets + 1)
				{
					char buffer[BUFFER_SIZE] = { 0 };
					recv(this->clientFd, buffer, BUFFER_SIZE, 0);
				}

				free(payload);
				free(request);
			}
		}

		free(header);
		file.close();
	}

	else
	{
		cerr << "Can't open file\n";
		return FAILURE;
	}
	
	return SUCCESS;
}

/* Receive the checksum of the file sent to the server:
*******************************************************
*	1. calculate the checksum					      *
*	2. compare the checksum to the server checksum    *
******************************************************/
unsigned int ClientHandler::receivedChecksum(const uint32_t payloadSize, const char* buffer, unsigned int offset)
{
	unsigned long checksum = 0;
	string UUID = "";
	string UUIDAscii = "";
	uint32_t encryptedFileSize = 0;
	uint32_t checksumFromServer = 0;
	string fileName = "";

	UUID.assign(buffer + offset, UUID_SIZE/2);
	UUIDAscii.assign(UUIDHandler::UUIDToAscii(reinterpret_cast<const unsigned char*>(UUID.c_str())), UUID_SIZE);
	offset += UUID_SIZE / 2;

	memcpy(&encryptedFileSize, buffer + offset, sizeof(uint32_t));
	encryptedFileSize = ntohl(encryptedFileSize);
	offset += sizeof(uint32_t);

	fileName.assign(buffer + offset, FILE_NAME_MAX_LENGTH);
	offset += FILE_NAME_MAX_LENGTH;

	memcpy(&checksumFromServer, buffer + offset, sizeof(uint32_t));
	checksumFromServer = ntohl(checksumFromServer);
	offset += sizeof(uint32_t);

	checksum = Cksum::calculateChecksum("test.txt");
	//cout << checksum << endl << checksumFromServer << endl;
	// checksums don't match
	if(checksum != checksumFromServer)
		return FAILURE;

	// checksums match
	return SUCCESS;
}

/* Send the checksum status to the server:
******************************************
*	1. Correct checksum                  *
*	2. Incorrect checksum, trying again  *
*	3. Incorrect checksum, aborting      *
*****************************************/
unsigned int ClientHandler::checksumStatus(const int requestCode, string fileName)
{
	char* header = NULL;
	char* payload = NULL;
	char* request = NULL;

	unsigned int headerOffset = 0;
	unsigned int payloadOffset = 0;
	uint32_t payloadSize = 0;

	header = packHeader(requestCode);
	headerOffset = UUID_SIZE / 2 + sizeof(uint8_t) + sizeof(uint16_t);

	fileName.resize(FILE_NAME_MAX_LENGTH, '\0');
	payloadSize = fileName.length();
	payloadSize = htonl(payloadSize);
	memcpy(header + headerOffset, &payloadSize, sizeof(uint32_t));
	headerOffset += sizeof(uint32_t);
	payloadSize = htonl(payloadSize);

	payload = (char*)malloc(fileName.length());

	memcpy(payload, fileName.c_str(), fileName.length());
	payloadOffset += fileName.length();

	request = (char*)malloc(headerOffset + payloadOffset);

	memcpy(request, header, headerOffset);
	memcpy(request + headerOffset, payload, payloadOffset);

	send(this->clientFd, request, headerOffset + payloadOffset, 0);

	free(request);
	free(header);
	free(payload);

	return SUCCESS;
}