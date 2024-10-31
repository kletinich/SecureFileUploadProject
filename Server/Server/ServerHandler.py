import Utilities
import socket
import struct
import uuid
import sys
import threading

import Codes
from CryptoHandler import CryptoHandler
from FileHandler import FileHandler
from ClientList import ClientNode

DEFAULT_PORT = 1256 
SERVER_HOST = '127.0.0.1'

MAX_NUM_OF_CONNECTIONS = 3 # size of the socket listen queue
BUFFER_SIZE = 1024 # size of reading buffer

CLIENT_ID_BYTES = 16 # size of client UUID in bytes
CLIENT_VERSION_BYTES = 1 # size of client version in bytes
REQUEST_CODE_BYTES = 2 # size of request code in bytes
PAYLOAD_SIZE_BYTES = 4 # size of payload size in bytes

FILE_NAME_LENGTH = 255 # max size of file name
FILE_SIZE_BYTES = 4 # size of file length in bytes
PACKET_NUM_SIZE_BYTES = 2 # size of packet number in bytes
CHECKSUM_SIZE_BYTES = 4 # size of checksum in bytes

SUCCESS = 1
FAILURE = 0

class ServerHandler:
    def __init__(self):
        self.serverPort = DEFAULT_PORT # the port of the server
        self.serverFd = 0 # file decryptor of the server
        self.serverVersion = sys.version.split('.')[0] # the major version of the server (3 for python 3.)
        self.currentNumOfClients = 0
        
        self.listOfClients = FileHandler.getClientsFromClientsFile()

        self.socketStatus = SUCCESS
        
        self.setPort()
        self.setSocket()
        
        if SUCCESS == self.socketStatus:
            self.listen()
        
    # Set the port of the server.
    def setPort(self):
        port = FileHandler.getPortFromPortFile()
        if port != None:
            self.serverPort = port   
        
    # Set the server socket
    def setSocket(self):
        try:
            self.serverFd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serverFd.bind((SERVER_HOST, self.serverPort))
            self.serverFd.listen(MAX_NUM_OF_CONNECTIONS)

        except:
            print("Error with creating socket")
            self.socketStatus = FAILURE
            
    # Waiting for clients
    def listen(self): 
        print("listening")
        
        lock = threading.Lock()
        
        while True:   
                if self.currentNumOfClients < MAX_NUM_OF_CONNECTIONS:    
                    clientFd, clientAddress = self.serverFd.accept()
                    
                    with lock:
                        self.currentNumOfClients += 1
                        
                    clientThread = threading.Thread(target=self.handleRequests, args=(clientFd, lock,))
                    clientThread.start()
            
        self.serverFd.close()
        print("Server closed")
      
    # Connected to a client. Handle its requests
    def handleRequests(self, clientFd, lock):
        clientUUID = ""
        clientName = ""
        clientVersion = 0
        requestCode = 0
        payloadSize = 0
        payload = ""
        
        while True:
            try:
                data = clientFd.recv(BUFFER_SIZE)
                            
                if len(data) == 0:
                    break
                
                offset = CLIENT_ID_BYTES
            
                clientVersion = struct.unpack("B", data[offset:offset + CLIENT_VERSION_BYTES])[0]
                offset += CLIENT_VERSION_BYTES

                requestCode = struct.unpack(">H",data[offset:offset + REQUEST_CODE_BYTES])[0]  
                offset += REQUEST_CODE_BYTES
                  
                payloadSize = struct.unpack(">I", data[offset:offset + PAYLOAD_SIZE_BYTES])[0]
                offset += PAYLOAD_SIZE_BYTES

                if requestCode != Codes.FILE_SEND_CODE and \
                    requestCode != Codes.CORRECT_CRC_CODE and \
                    requestCode != Codes.INCORRECT_CRC_SEND_AGAIN_CODE and \
                    requestCode != Codes.INCORRECT_CRC_ABORT_CODE:
                    payload = data[offset:offset + payloadSize - 1].decode("utf-8")

                else:
                    payload = data[offset:offset + payloadSize - 1]  
            
                if Codes.REGISTER_REQUEST_CODE == requestCode or Codes.RECONNECTION_REQUEST_CODE == requestCode:
                    clientName = payload
                    print("Established connection with " + clientName + " (version " + str(clientVersion) + ")")
                
                if Codes.REGISTER_REQUEST_CODE != requestCode:
                    clientUUID = data[:CLIENT_ID_BYTES].hex()
  
                # Handle registration request
                if Codes.REGISTER_REQUEST_CODE == requestCode:
                    self.handleRegisterRequest(clientFd, clientName)
                
                # Handle public key from client. Should be handled after registration
                elif Codes.PUBLIC_KEY_SEND_CODE == requestCode:
                    self.handlePublicKeyRequest(clientFd, clientName, clientUUID, payload)
                
                # Handle reconnection request
                elif Codes.RECONNECTION_REQUEST_CODE == requestCode:
                    self.handleRecconectionRequest(clientFd, clientName, clientUUID)
                
                # Handle file chunk receieved from the client
                elif Codes.FILE_SEND_CODE == requestCode:
                    self.handleFileChunkReceivedFromClient(clientFd, clientName, clientUUID, payload)
                
                # Hanlde received CRC status = correct CRC or incorrect CRC abort message
                elif Codes.INCORRECT_CRC_ABORT_CODE  == requestCode or \
                        Codes.CORRECT_CRC_CODE == requestCode:
                    self.respondToCRCStatus( requestCode, clientFd, clientName, clientUUID, payload)

                    
            except ConnectionResetError:
                clientFd.close()
                break
                        
        # save all the clients to clients file. Like a database
        with lock:
            FileHandler.saveClientsInClientsFile(self.listOfClients)
            print(clientName + " disconnected")
            self.currentNumOfClients -= 1
                   
        return SUCCESS
                          
    # Handling the register request. 
    # Return Success on successfull registration or fulure for failed registration
    def handleRegisterRequest(self, clientFd, clientName):
        print(clientName + ": Attempt to register")
        found = self.listOfClients.searchClient(clientName)

        # Client exists in the server. Send REGISTER FAILURE code
        if found:
            data = Utilities.packMessageHeader(self.serverVersion, Codes.REGISTER_FAILURE_CODE, 0)
            print(clientName + ": Client already registered")
            clientFd.send(data)
            return FAILURE
            
        # Client doesn't exist. Allow him to register, generate a UUID for him
        clientUUID = self.generateUUIDForClient(clientName)
      
        # Couldn't generate UUID / save client for some reason
        if clientUUID == None:
            data = Utilities.packMessageHeader(self.serverVersion, Codes.GENERAL_ERROR_CODE, 0)
            print(clientName + ": General error occured while registering")
            clientFd.send(data)
            return FAILURE
        
        # Client saved successfully. Send the generated UUID to him
        FileHandler.createFolderForClient(clientUUID)
        data = Utilities.packMessageHeader(self.serverVersion, Codes.REGISTER_SUCCESS_CODE, len(clientUUID.bytes))
        data += clientUUID.bytes
        print(clientName + ": Client registered successfully")
        clientFd.send(data)
        return SUCCESS
         
    # Generate a UUID for the client and save the new client in the list of clients.
    # Return the UUID if success and if some error occured return null
    def generateUUIDForClient(self, clientName):
        try:
            UUID = uuid.uuid4()
            
        except Exception as e:
            print("An exception occured while generating UUID")
            return None
        
        newClient = ClientNode(clientName, UUID)
        addStatus = self.listOfClients.addClient(newClient)
        
        if addStatus == SUCCESS:
            return UUID
        
        return None
    
    # Get a public key from the client. Generate an Aes key and send the client an encrypted Aes key
    def handlePublicKeyRequest(self, clientFd, currentClientName, clientUUID, payload):
        if currentClientName == "" or clientUUID == "":
            data = Utilities.packMessageHeader(self.serverVersion, Codes.GENERAL_ERROR_CODE, 0)
            print("Error while receiving public key from: " + currentClientName)
            clientFd.send(data)
            return FAILURE
        
        nameLength = len(currentClientName)
        clientName = payload[:nameLength]
        clientPublicKey = payload[nameLength:]

        # Get an AES key and its encrypted version
        aesKey, encryptedAesKey = CryptoHandler.generateAndEncryptAESKey(clientPublicKey)
        
        if not self.listOfClients.saveKeys(clientName,Utilities.formatUUIDWithDashes(clientUUID), aesKey, encryptedAesKey):
            data = Utilities.packMessageHeader(self.serverVersion, Codes.GENERAL_ERROR_CODE, 0)
            print(clientName + ": General error occured while trying to save keys")
            clientFd.send(data)
            return FAILURE
        
        clientUUID = bytes.fromhex(clientUUID)
        clientUUID = uuid.UUID(bytes=clientUUID)
        
        # Sending the client success message with clientUUID and the encrypted aes key
        data = Utilities.packMessageHeader(self.serverVersion, Codes.AES_SEND_CODE, CLIENT_ID_BYTES + len(encryptedAesKey))
        data += clientUUID.bytes
        data += encryptedAesKey
        print(clientName + ": Sent encrypted AES key to client")
        clientFd.send(data)
        
        return SUCCESS
    
    # Handle the reconnection request.
    # Send the encrypted Aes key previosly generated to the client
    def handleRecconectionRequest(self, clientFd, clientName, clientUUID):
        print(clientName + ": Attempt to reconnect")
        client = self.listOfClients.getClient(clientName, Utilities.formatUUIDWithDashes(clientUUID))
        
        clientUUID = bytes.fromhex(clientUUID)
        clientUUID = uuid.UUID(bytes=clientUUID)
        
        # Client doesn't exsist in the server. Can't reconnect
        if(client == None):   
            data = Utilities.packMessageHeader(self.serverVersion, Codes.RECONNECTION_DECLINED_CODE, CLIENT_ID_BYTES)
            data += clientUUID.bytes
            print(clientName + ": Can't reconnect. Client doesn't exist in the server")
       
        # Client exists. Sending the encrypted aes key previosly generated
        else:     
            client = self.listOfClients.getClient(clientName, str(clientUUID))
            encryptedAesKey = client.encryptedAesKey 
            data = Utilities.packMessageHeader(self.serverVersion, Codes.RECONNECTION_SUCCESS_CODE, CLIENT_ID_BYTES + len(encryptedAesKey))
            data += clientUUID.bytes
            data += encryptedAesKey 
            print(clientName + ": Client reconnected successfully. Sending encrypted AES key")

        clientFd.send(data)
        
    # Receive a chunk of a file from the client.
    def handleFileChunkReceivedFromClient(self, clientFd, clientName, clientUUID, payload):
        offset = 0

        encryptedFileSize = struct.unpack(">I", payload[:FILE_SIZE_BYTES])[0]
        offset += FILE_SIZE_BYTES
        
        originalFileSize = struct.unpack(">I", payload[offset:offset + FILE_SIZE_BYTES])[0]
        offset += FILE_SIZE_BYTES
        
        currentPacketNumber = struct.unpack(">H",payload[offset:offset + PACKET_NUM_SIZE_BYTES])[0]
        offset += PACKET_NUM_SIZE_BYTES
        
        numOfPackets = struct.unpack(">H", payload[offset:offset + PACKET_NUM_SIZE_BYTES])[0]
        offset += PACKET_NUM_SIZE_BYTES
        
        fileName = payload[offset:offset + FILE_NAME_LENGTH].decode("utf-8")
        offset += FILE_NAME_LENGTH
        
        encryptedContent = payload[offset:]
        if currentPacketNumber == 1:
            print(clientName + ": Attempt to receive encrypted file '" + fileName + "'")
            
        client = self.listOfClients.getClient(clientName, Utilities.formatUUIDWithDashes(clientUUID))
        aesKey = client.aesKey

        # decrypting and appending the packet content to a file
        decryptedContent = CryptoHandler.decryptWithAESKey(aesKey, encryptedContent)

        FileHandler.addDecryptedDataToClientFile(Utilities.removeNullCasesFromFileName(fileName), Utilities.formatUUIDWithDashes(clientUUID), decryptedContent, currentPacketNumber) 

        if currentPacketNumber < numOfPackets:
            clientFd.send(fileName.encode("utf-8"))
            
        #received the last packet
        elif currentPacketNumber == numOfPackets:
            checksum = Utilities.calculateChecksum(Utilities.removeNullCasesFromFileName(fileName), Utilities.formatUUIDWithDashes(clientUUID))
            payloadSize = CLIENT_ID_BYTES + FILE_SIZE_BYTES + FILE_NAME_LENGTH + CHECKSUM_SIZE_BYTES 
            data = Utilities.packMessageHeader(self.serverVersion, Codes.FILE_RECEIVED_SUCSSESSFULY_CODE, payloadSize)

            clientUUID = bytes.fromhex(clientUUID)
            clientUUID = uuid.UUID(bytes=clientUUID)
            data += clientUUID.bytes
            data += struct.pack(">I", encryptedFileSize)
            data += fileName.encode("utf-8")
            data += struct.pack(">I", checksum)
            print("Sending checksum to: " + clientName)
            
            clientFd.send(data)
          
    # Respond to the CRC status got from the client
    def respondToCRCStatus(self, requestCode, clientFd, clientName, clientUUID, payload):
        fileName = payload[:FILE_NAME_LENGTH].decode("utf-8")
     
        print(clientName + ": '" + fileName + "' " , end="")

        if(Codes.CORRECT_CRC_CODE == requestCode):
            print("CRC confirmed")
        else:
            print("Failed 4th attempt to confirm CRC. Aborting")
     
        clientUUID = bytes.fromhex(clientUUID)
        clientUUID = uuid.UUID(bytes=clientUUID)
        
        payloadSize =  CLIENT_ID_BYTES   
        data = Utilities.packMessageHeader(self.serverVersion, Codes.ACCEPT_MESSAGE_THANKS_CODE, payloadSize)
        data += clientUUID.bytes
        clientFd.send(data)
           
        
       