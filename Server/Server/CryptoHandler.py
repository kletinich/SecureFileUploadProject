from pickletools import read_stringnl_noescape_pair
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

AES_KEY_SIZE = 16

class CryptoHandler:
    
    # Generate an AES key and encrypt it with RSA key
    @staticmethod
    def generateAndEncryptAESKey(clientPublicKey):
        aesKey = get_random_bytes(AES_KEY_SIZE)
        rsaKeyBytes = base64.b64decode(clientPublicKey)
        rsaKey = RSA.import_key(rsaKeyBytes)
        cipherRsa = PKCS1_OAEP.new(rsaKey)
        encryptedAesKey = cipherRsa.encrypt(aesKey)
  
        return [aesKey, encryptedAesKey]

    # Decrypt cipher text with a given AES key
    @staticmethod
    def decryptWithAESKey(aesKey, cipherText): # TO DO: FINISH
        iv = bytes([0] * AES.block_size)
        cipher = AES.new(aesKey, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(cipherText)
        return decrypted_data
