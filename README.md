# secure-channels
Douglas Webster and Jay Rodolitz

This is a self contained demonstration of man-in-the-middle attacks on encrypted communication, in python 3. 



Detailed Setup

This system runs on python 3 and requires the pycryptodome package, which can be installed with pip pycryptodome.
It can be run on any system, but requires the ability to use localhost.

Running the system
Open four terminal windows to this directory. Decide what kind of encryption/mac scheme you want (this is the string you will pass to Alice, Bob, and Mallory as their first argument)
    - 'noCrypto': no cryptography is used and messages are not protected.
    - 'enc': AES encryption is used to protect the confidentiality of messages, but no MAC is used.
    - 'mac': MACs are used to protect the integrity of messages.
    - 'EncthenMac': AES encryption is followed by MAC hashing to protect both the confidentiality and integrity of messages 

In the first, run gen, to generate your keys: 
> python3 gen.py 

Next, run Bob, the client program, in a new terminal:
> python3 Bob.py noCrypto 8122

The first argument is the encryption mode, any of 'noCrypto', 'enc', 'mac' , or 'EncthenMac'
The second argument is the port Bob will listen for messages at (ex: 8122)

Once Bob is running, run Mallory in the next terminal, using the same bob_port value and encryption_mode
> python3 Mallory.py noCrypto 127.0.0.1 8100 8122

The first argument is the encryption_mode,'noCrypto', 'enc', 'mac' , or 'EncthenMac'
The second argument is the host (ex: 127.0.0.1)
Third is the port Alice will send messages to (ex 8100)
Fourth, the port Bob is listening for messages at (ex: 8122)

Finally, run Alice in a new terminal, using the alice_port from mallory and the encryption_mode you've been using:
> python3 Alice.py noCrypto 127.0.0.1 8100

The first argument is the encryption_mode, from 'noCrypto', 'enc', 'mac' , or 'EncthenMac'
The second, the host connection (ex: 127.0.0.1)
The third, the port Alice will send messages to (ex 8100)

Now Alice will prompt for messages, which will be encrypted (potentially) and sent to Mallory. Mallory will display the message, and prompt the user to either
1: send the message as is
2: edit the message
3: drop the message
4: store the message
5: replay the stored message

Whatever message Mallory decides to pass on will be sent to Bob

When Bob recieves a message it will decrypt it (if applicable), and detect tampering by verifying that this is, in fact, the next message in the sequence Alice has sent as well as verifying the SHA hash for the message (if mac is used). It will then display the message. 





Overview doc stuff here (move me later):
This system operates over TLS using IS_ 11770-3 Key Transport Mechanism 2 with RSA(PKCS1_OAEP and SSA-PSS) to distribute keys for AES_128_CBC and SHA256. It offers the choice of running with no cryptography, AES encryption, and/or SHA hashing.

This system operates over TLS, so the assumption can be made that every message Alice sends will reach Bob in order (in practice this is complicated by the existence of Mallory, the MitM attacker). 
It generates and distributes 2048 bit RSA keys for Alice and Bob before running, so that they may be used for key distribution. 2048 bits is NIST standard.
Keys for AES and SHA are distributed using the ISO/IEC 11770-3 Key Transport Mechanism 2, which enables Alice to convey a key to Bob in a single message (encrypting the key and signing the message). This does not require Bob to respond or convey any information back. This protocol is encrypted and signed using the RSA keys previously generated. The encryption uses PKCS1_OAEP, the IETF recommended specification for RSA as of 2016 and a non-malleable, padded form of RSA. The digital signature uses RSASSA-PSS, described in the same document. As this is a malleable cipher, it is further hashed with the SHA256 MAC described later in the document. This protocol is described by the IETF, and maintains confidentiality and integrity of the key.
The system uses AES_128_CBC as a block cipher to encrypt messages from alice in the enc and EncthenMac conditions. This specification is defined in NIST SP 800-38A, section 6.2, and ensures that the ciphertext doesn't contain internal repetition by xoring plaintext blocks with the preceding ciphertext blocks. However, it very explicitly does not maintain the integrity of messages through hashing, unlike something like Galois Counter Mode. This is an intentional decision, as we wanted to be able to turn hashing on and off trivially. 
To verify that messages haven't been tampered with, the system uses SHA256 to authenticate messages. While this hash is vulnerable to length extension attacks and replay attacks, we do not need to worry about length extension while encrypted (as without knowledge of the AES key, an attacker cannot *add* blocks to a message undetectedly, only remove them), and our vulnerability to replay attacks 

message packets are formed as follows
message_number [hash] [iv] message 
the first four bytes are the message number, a plaintext int that is NOT hashed when mac is enabled
if mac is enabled, the next 256 bytes are the SHA hash
if encryption is enabled, the next 16 bytes are the IV for the cipher text
the rest of the packet contains the message (either in plain or cipher text depending on the condition)


External Libraries Used
- pycryptodome: this library is used to do all of our cryptography: generating random byte strings for RSA, AES and MAC keys and implementing RSA, AES and MAC algorithms

Known Problems
- Alice has no way of knowing if Bob has recieved the messages sent//if they're being altered, because Bob cannot communicate back to Alice
- If messages are mispackaged (by mallory), unexpected behavior will occur when they're recieved by bob
- Message numbers are passed in unhashed plaintext such that Mallory can trivially modify them. (this is an intentional decision for the purposes of attack 5 - we can consider and trivially alter the system such that the number is appended to the end of the message before encryption and hashing, such that an attacker must be able to accurately modify messages undetected to perform a replay attack)
- Mallory doesn't currently keep track of the message number Bob is expecting, and will crash the system once it passes through a message after dropping an old one. 