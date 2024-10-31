SUCCESS = 1
FAILURE = 0

class ClientNode:
    def __init__(self, username, UUID):
        self.username = username
        self.UUID = UUID

        self.aesKey = None
        self.encryptedAesKey = None
        self.next = None
        
class ClientList:
    def __init__(self):
        self.head = None
           
    # adds a client to the list
    def addClient(self, newNode): 
        try:
            if self.head == None:
                self.head = newNode
                return SUCCESS
            
            clientNode = self.head
            
            while(clientNode.next != None):
                clientNode = clientNode.next
            clientNode.next = newNode
            return SUCCESS
        
        except Exception as e:
           return FAILURE
    
    # search if a client with a given username exists in the clients list for registration.
    def searchClient(self, username):
        clientNode = self.head
        while clientNode != None:
            if(clientNode.username == username):
                return True
            clientNode = clientNode.next
        
        return False
    
    # search for a client with the given userName and UUID. If found update the public key
    # and the aes key. If not, the client with the userName and UUID doesn't exists.
    def saveKeys(self, username, UUID, aesKey, encryptedAesKey):
        clientNode = self.head
        while(clientNode != None):
            if(clientNode.username == username and str(clientNode.UUID) == UUID):
                clientNode.aesKey = aesKey
                clientNode.encryptedAesKey = encryptedAesKey
                
                return SUCCESS
            
            clientNode = clientNode.next
        
        return FAILURE
    
    # search for a client with a given username and UUID (for validation)
    # and if the client with the same username and UUID doesn't exists, return null
    def getClient(self, username, UUID):
        clientNode = self.head

        while clientNode != None:
            if(clientNode.username == username and str(clientNode.UUID) == UUID):
                return clientNode
            
            clientNode = clientNode.next
            
        return None
    
