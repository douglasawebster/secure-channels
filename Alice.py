import sys
import socket
import json
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from Crypto.Hash import HMAC, SHA256

# generate an AES CBC cipher for the session
# takes a RSA key
# return a tuple containing
# enc_session_key, the AES key encrypted by the RSA key
# cipher_aes, the cipher object
def generate_session_key(public_key):
    session_key = get_random_bytes(16)
    print("Session Key: ", session_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return (session_key, enc_session_key)

# generate a random 256 bit string for use as a mac key
def generate_mac_key():
    return get_random_bytes(256)
    
# encrypt a message with an AES CBC cipher
# takes a string msg to encode
# and the aes session key
# return a string beginning with the initialization vector, followed by the encrypted message
def encrypt(msg, session_key): #, cipher_aes):
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(msg, AES.block_size))
    iv = b64encode(cipher_aes.iv).decode('utf-8')
    cipher_text = b64encode(ct_bytes).decode('utf-8')
    result = iv + cipher_text

    print("IV: ", iv)
    print()
    print("Cipher: ", cipher_text)

    return result

# return the hash for string msg using the sha256 HMAC with bytes of key
def create_mac(msg, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(msg.encode())
    return h.hexdigest()

# reads in alice's private key and bob's public key
# in preperation for encryption 
def read_keys():
    f = open("./keys/alice_priv.pem", 'rb')
    alice_private_key = RSA.import_key(f.read())
    f.close()

    f = open("./keys/alice_public.pem", 'rb')
    alice_public_key = RSA.import_key(f.read())
    f.close()

    f = open("./keys/bob_public.pem", 'rb')
    bob_public_key = RSA.import_key(f.read())
    f.close()

    return (alice_private_key, alice_public_key, bob_public_key)

def main():

    # parse arguments
    if len(sys.argv) != 4:
        print("usage: python3 %s <host> <port> <config> % sys.argv[0]")
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]
    config = sys.argv[3]
 

    # set up encryption configuration
    if config == "noCrypto":
        enc = False
        mac = False
    elif config == "enc":
        enc = True
        mac = False
    elif config == "mac":
        enc = False
        mac = True
    elif config == "EncThenMac":
        enc = True
        mac = True
    else:
        print("invalid configuration "+ config + " valid configuration options: noCrypto, enc, mac, EncThenMac")
        quit(1)
    # open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to server")
    # connect to server
    clientfd.connect((host, int(port)))

    alice_private_key, alice_public_key, bob_public_key = read_keys()

    # load requested tools
    session_key = None
    enc_session_key = None
    mac_key = None
    enc_mac_key = None

    if enc and mac:
        session_key, enc_session_key = generate_session_key(bob_public_key)
        # send bob session key encrypted with NONMALLEABLE RSA (i think?)
        # (this means we don't need MAC)
        # (need to check this assumption lmaooo)
        clientfd.send(enc_session_key)       

        mac_key = generate_mac_key()
        #the mac key encrypted under AES (of the form [iv+mac key])
        enc_mac_key = encrypt(mac_key, session_key) 
        mac2 = create_mac(enc_mac_key, mac_key)
        msg = mac2 + enc_mac_key
        # mac hash
        # 16-40: macIV
        # 40- : encrypted mac key
        print(mac_key)
        clientfd.send(msg.encode())

    elif enc:
        session_key, enc_session_key = generate_session_key(bob_public_key) 
        clientfd.send(enc_session_key)
    elif mac:
        mac_key = generate_mac_key()
        clientfd.send(mac_key)

    ctr = 0
    # message loop
    while(True):
        msg = input("Enter message: ")
        # TODO: make sure we send the session key over in the first message
        # send encrypted message with mac tag
        if enc and mac:
            enc_message = encrypt(msg.encode(), session_key)
            mac2 = create_mac(enc_message, mac_key)
            print(mac2)

            msg = mac2 + enc_message
            clientfd.send(msg.encode())
        
        # send encrypted message with no tags
        elif enc:
            enc_message = encrypt(msg.encode(), session_key)
            clientfd.send(enc_message.encode())

        # send plaintext with mac tag (because that's sooooooo useful)
        elif mac: 
            mac2 = create_mac(msg, mac_key)
            print(mac2)
            msg = mac2 +  msg
            clientfd.send(msg.encode('utf-8'))
        
        # send message in plaintext without mac
        else:
            clientfd.send(msg.encode())

#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    clientfd.close()

if __name__ == "__main__":
    main()


