import sys
import socket
import json
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from base64 import b64encode

# generate an AES CBC cipher for the session
# takes a RSA key
# return a tuple containing
# enc_session_key, the AES key encrypted by the RSA key
# cipher_aes, the cipher object
def get_session_key(rsa_key):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_CBC)

    return (enc_session_key, cipher_aes)

# encrypt a messaage with an AES CBC cipher
def encrypt(data, cipher_aes):
    ct_bytes = cipher_aes.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher_aes.iv).decode('utf-8')
    cipher_text = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':cipher_text})
    print(result)

    return result

# reads in alice's private key and bob's public key
# in preperation for encryption 
def read_keys():
    global alice_private_key, bob_public_key
    f = open("./keys/alice_priv.pem", 'rb')
    alice_private_key = RSA.import_key(f.read())
    f.close()
    f = open("./keys/bob_public.pem", 'rb')
    bob_public_key = RSA.import_key(f.read())
    f.close()

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

    

    # open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("connecting to server")
    # connect to server
    clientfd.connect((host, int(port)))


    # load crypto tools if needed
    enc_session_key = None
    cipher_aes = None
    if enc:
        read_keys()
        (enc_session_key, cipher_aes) = get_session_key(bob_public_key) 
        clientfd.send(enc_session_key)
    if mac:
        read_mac()


    # message loop
    while(True):
        msg = input("Enter message for server: ")
        # TODO: make sure we send the session key over in the first message
        if enc:
            message = encrypt(msg.encode(), cipher_aes)
            clientfd.send(message.encode())

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


