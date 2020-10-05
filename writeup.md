A3 secure channels Douglas and Jay

This system operates over TLS using IS_ 11770-3 Key Transport Mechanism 2 with RSA(PKCS1_OAEP and SSA-PSS) to distribute keys for AES_128_CBC and SHA256. It offers the choice of running with no cryptography, AES encryption, and/or SHA hashing.

This system operates over TLS, so the assumption can be made that every message Alice sends will reach Bob in the order they were sent (in practice this is complicated by the existence of Mallory, the MitM attacker). 

It generates and distributes 2048 bit RSA keys for Alice and Bob before running, so that they may be used for key distribution. 2048 bits is NIST standard.

Keys for AES and SHA are distributed using the ISO/IEC 11770-3 Key Transport Mechanism 2, which enables Alice to convey a key to Bob in a single message (encrypting the key and signing the message). This does not require Bob to respond or convey any information back. This protocol is encrypted and signed using the RSA keys previously generated. 
The encryption uses PKCS1_OAEP, the IETF recommended specification for RSA as of 2016 and a non-malleable, padded form of RSA. The digital signature uses RSASSA-PSS, described in the same document. As this is a malleable cipher, it is further hashed with the SHA256 MAC described later in the document. This protocol is described by the IETF, and maintains confidentiality and integrity of the key.

The system uses AES_128_CBC as a block cipher to encrypt messages from Alice in the enc and EncthenMac conditions. This specification is defined in NIST SP 800-38A, section 6.2, and ensures that the ciphertext doesn't contain internal repetition by xoring plaintext blocks with the preceding ciphertext blocks. However, it very explicitly does not maintain the integrity of messages through hashing, unlike something like Galois/Counter Mode. This is an intentional decision, as we wanted to be able to turn hashing on and off trivially. 

To verify that messages haven't been tampered with, the system uses SHA256 to authenticate messages. While this hash is vulnerable to length extension attacks and replay attacks, we do not need to worry about length extension while encrypted (as without knowledge of the AES key, an attacker cannot *add* blocks to a message undetectedly, only remove them), and our vulnerability to replay attacks 

message packets are formed as follows:
message_number [hash] [iv] message 
the first four bytes are the message number, a plaintext int that is NOT hashed when mac is enabled
if mac is enabled, the next 256 bytes are the SHA hash
if encryption is enabled, the next 16 bytes are the IV for the cipher text
the rest of the packet contains the message (either in plain or cipher text depending on the condition)


External Libraries Used
- pycryptodome: this library is used to do all of our cryptography: generating random byte strings for RSA, AES and MAC keys and implementing RSA, AES and MAC algorithms

Known Problems
- Alice has no way of knowing if Bob has recieved the messages sent//if they're being altered, because Bob cannot communicate back to Alice
- If messages are mispackaged (by Mallory), unexpected behavior will occur when they're recieved by Bob
- Message numbers are passed in unhashed plaintext such that Mallory can trivially modify them. (this is an intentional decision for the purposes of attack 5 - we can consider and trivially alter the system such that the number is appended to the end of the message before encryption and hashing, such that an attacker must be able to accurately modify messages undetected to perform a replay attack)
- Mallory doesn't currently keep track of the message number Bob is expecting, and will crash the system once it passes through a message after dropping an old one, as Bob is expecting a different number than it recieves.
-in NoCrypto bob doesn't verify the identity of Alice