# secure-channels
Douglas Webster and Jay Rodolitz

This is a self contained demonstration of man-in-the-middle attacks on encrypted communication, in python 3. 



Detailed Setup

This system runs on python 3 and requires the pycryptodome package, which can be installed with pip pycryptodome.
It can be run on any system, but requires the ability to use localhost.

2. Running the system
Open four terminal windows to this directory. Decide what kind of encryption/mac scheme you want (this is the string you will pass to Alice, Bob, and Mallory as their first argument)
    - 'noCrypto': no cryptography is used and messages are not protected.
    - 'enc': AES encryption is used to protect the confidentiality of messages, but no MAC is used.
    - 'mac': MACs are used to protect the integrity of messages.
    - 'EncthenMac': AES encryption is followed by MAC hashing to protect both the confidentiality and integrity of messages 

In the first, run gen, to generate your keys: 
> python3 gen.py 

Next, run Bob, the client program, in a new terminal:
> python3 Bob.py <encryption_mode> <bob_port>
<encryption_mode> = 'noCrypto', 'enc', 'mac' , or 'EncthenMac'
<bob_port> = the port Bob will listen for messages at (ex: 8122)

Once Bob is running, run Mallory in the next terminal, using the same bob_port value and encryption_mode
> python3 Mallory.py <encryption_mode> <host> <alice_port> <bob_port>
<encryption_mode> = 'noCrypto', 'enc', 'mac' , or 'EncthenMac'
<host> = the host connection (ex: 127.0.0.1)
<alice_port> = the port Alice will send messages to (ex 8100)
<bob_port> = the port Bob is listening for messages at (ex: 8122)

Finally, run Alice in a new terminal, using the alice_port from mallory and the encryption_mode you've been using:
> python3 Alice.py <encryption_mode> <host> <alice_port> 
<encryption_mode> = 'noCrypto', 'enc', 'mac' , or 'EncthenMac'
<host> = the host connection (ex: 127.0.0.1)
<alice_port> = the port Alice will send messages to (ex 8100)

Now Alice will prompt for messages, which will be encrypted (potentially) and sent to Mallory. Mallory will display the message, and prompt the user to either
1: send the message as is
2: edit the message
3: drop the message

Whatever message Mallory decides to pass on will be sent to Bob

When Bob recieves a message it will decrypt it (if applicable), and tampering by verifying that this is, in fact, the next message in the sequence Alice has sent, and verifying the mac hash for the message (if mac is used). It will then display the message. 





Overview doc stuff here (move me later):
(TODO rationale: why key lengths chosen??)
1. Rationale:
This system uses enables four levels of cryptography for varying levels of integrity and confidentiality. 
- if you don't care about either, the system lets you send plaintext messages back and forth
- if you wish to ensure confidentiality but don't care about integrity, the system will allow you to use RSA-OAEP to securely distribute a key for symmetric AES-CBC encryption. (CBC explicitly doesn't maintain integrity)
- If you wish to ensure 

2. Specification

3. External Libraries
- pycryptodome: this library is used to do all of our cryptography: generating random byte strings for RSA, AES and MAC keys and implementing RSA, AES and MAC algorithms

4. known problems
- we don't have a secure handshake to establish keys: Mallory could send over any key encrypted with bob's RSA and pretend to be Alice, and this is undetectable at the moment
- Alice has no way of knowing if Bob has recieved the messages sent//if they're being altered, because Bob cannot communicate back to Alice
- 