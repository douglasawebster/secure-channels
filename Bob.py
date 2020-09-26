import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from base64 import b64decode
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
import base64
import json

def verify_mac(msg, mac, key):
    #secret = key.exportKey('PEM')
    h = HMAC.new(key, digestmod=SHA256)
    print(msg)
    print()
    print(mac)
    h.update(msg.encode())

    try: 
        h.hexverify(mac)
        return True
    except:
        return False

def decrypt(data, session_key):
    try:
        b64 = json.loads(data)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except ValueError:
        print("Incorrect decryption")

def decrypt_session_key(enc_session_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key) 
    return session_key

def read_keys():
    f = open('./keys/bob_priv.pem', 'rb')
    bob_private_key = RSA.import_key(f.read())
    f.close()

    f = open('./keys/bob_public.pem', 'rb')
    bob_public_key = RSA.import_key(f.read())
    f.close()

    f = open('./keys/alice_public.pem', 'rb')
    alice_public_key = RSA.import_key(f.read())
    f.close()

    return bob_private_key, bob_public_key, alice_public_key

# detect if a message has been tampered with
def detect_shennanigans(message):
    False


def main():
    
    # parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <port> <config>" % sys.argv[0])
        quit(1)

    # setting the port
    port = sys.argv[1]
    config = sys.argv[2]

    # set up encryption cnfiguration
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
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    listenfd.bind(('', int(port)))

    # listen to socket
    listenfd.listen(1)

    # accept connection
    (connfd, addr) = listenfd.accept()

    bob_private_key, bob_public_key, alice_public_key  = read_keys()

    # load crypto tools if needed
    session_key = None
    if enc: 
        enc_session_key = connfd.recv(1024)
        session_key = decrypt_session_key(enc_session_key, bob_private_key)
        print("SessionKey: ", session_key)

    mac_key = None
    if mac:
        mac_key = connfd.recv(1024)
        print("MacKey: ", mac_key)
        
    # message loop
    while(True):
        msg = connfd.recv(1024).decode()
        if(detect_shennanigans(msg)):
            print("the following message has been altered: %s" % msg)
        else:
            if enc:
                decrypted_msg = decrypt(msg, session_key)
                print("Received from client: %s" % decrypted_msg)
            else:
                print("Received from client: %s" % msg)

                mac = msg[:64]
                message = msg[64:]

                if verify_mac(message, mac, mac_key):
                    print("Message is authentic")
                else: 
                    print("Message has been altered")



        



#        # You don't need to send a response for this assignment
#        # but if you wanted to you'd do something like this
#        msg = input("Enter message for client: ")
#        connfd.send(msg.encode())

    # close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()
