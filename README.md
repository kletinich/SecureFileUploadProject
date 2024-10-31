# SecureFileUploadProject
This project implements a client-server architecture for secure file communication. It allows users to send and receive files over the network with encryption, ensuring that sensitive data remains protected during transmission.

Features:
- <p> Client-server model: <br> The project contains to seperate sides for the client, written in c++, and the server, written in python. </p>
  
- Hybrid encryption:
    Symetric encryption - for the initial client registration on the server side and the exchange of the private and public keys of each side.
    Asymetric encryption - for the rest of the communication between the client and the server.
  
- File integrity check:
    File integrity is verified using checksums, ensuring that files remain unaltered during transmission.
    This feature helps detect any corruption or tampering of data.
