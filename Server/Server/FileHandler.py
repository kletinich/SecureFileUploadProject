import binascii
import os
from ClientList import ClientNode, ClientList

PORT_INFO_FILE = 'port.info'
CLIENTS_INFO_FILE = 'clients.info'

class FileHandler:
    
    # Read the port from the port.info file. if file doesn't exist, return null
    @staticmethod
    def getPortFromPortFile():
        try:
            with open(PORT_INFO_FILE, "r") as portFile:
                return (int)(portFile.read()) 
            
        except FileNotFoundError:
            return None
        
    # Read a list of clients from clients.info file. Used instead of database usage
    @staticmethod
    def getClientsFromClientsFile():
        listOfClients = ClientList()
 
        try:
            clientFile = open(CLIENTS_INFO_FILE, "r")
            lines = clientFile.readlines()
            
            for i in range(len(lines)):
 
                if i % 4 == 0:
                    username = lines[i].strip()
                elif i % 4 == 1:
                    UUID = lines[i].strip()
                elif i % 4 == 2:
                    aesKey = lines[i].strip()
                    aesKey = binascii.unhexlify(aesKey[2: 34]) # not magic number
                elif i % 4 == 3:
                    encryptedAesKey = lines[i].strip()
                    encryptedAesKey = binascii.unhexlify(encryptedAesKey[2:258]) # not magic number
                    
                    clientNode = ClientNode(username, UUID)
                    listOfClients.addClient(clientNode)
                    listOfClients.saveKeys(username, UUID, aesKey, encryptedAesKey)
                
        except FileNotFoundError:
          pass
            
        finally:
            return listOfClients
    
    # Write the list of registered clients into client.info file. Used instead of database usage
    @staticmethod
    def saveClientsInClientsFile(listOfClients):
        clientsFile = open(CLIENTS_INFO_FILE, "w")
        clientNode = listOfClients.head

        while clientNode != None:
            username = clientNode.username
            UUID = clientNode.UUID
            aesKey = binascii.hexlify(clientNode.aesKey)
            encryptedAesKey = binascii.hexlify(clientNode.encryptedAesKey)
            
            clientsFile.write('\n'.join([username, str(UUID), str(aesKey), str(encryptedAesKey)]))\
        
            clientNode = clientNode.next
            
    @staticmethod
    def createFolderForClient(clientUUID):
        os.mkdir(str(clientUUID))
            
    # write decryped text to file on clientUUID path
    @staticmethod
    def addDecryptedDataToClientFile(fileName, clientUUID, text, packetNum):
        # stripping the fileName from null characters
        fileNameStripped = ""
        for i in range(len(fileName)):
            if ord(fileName[i]) == 0:
                break
            fileNameStripped += fileName[i]
        
        filePath = clientUUID + "/" + fileNameStripped

        if packetNum > 1:
            clientFile = open(filePath, 'a')
            clientFile.write(str(text))
        
        else:
            clientFile = open(filePath, 'w')
            clientFile.write(str(text))
            
        clientFile.close()