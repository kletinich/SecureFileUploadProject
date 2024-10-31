import struct
import Cksum

# Pack the header of a response to the client
def packMessageHeader(serverVersion, code, payloadSize):
    header = struct.pack(">B", int(serverVersion))
    header += struct.pack(">H", code)
    header += struct.pack(">I", payloadSize)

    return header

# Format a given UUID with dashes in the matching places
def formatUUIDWithDashes(UUID):
    formatedUUID = '-'.join([
        UUID[0:8],
        UUID[8:12],
        UUID[12:16],
        UUID[16:20],
        UUID[20:]
    ])
    
    return formatedUUID

# Remove all the nulls attached to a file name
def removeNullCasesFromFileName(fileName):
        fileNameStripped = ""
        for i in range(len(fileName)):
            if ord(fileName[i]) == 0:
                break
            fileNameStripped += fileName[i]
        return fileNameStripped
    
# Calculate the checksum of a file
def calculateChecksum(fileName, clientUUID):
    filePath = clientUUID + "/" + fileName
    checksum =  Cksum.readfile(filePath)   
    
    return checksum

    
    
    
    
    
