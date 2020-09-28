import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
import base64
import json

# Reads in bob's private key and alices's public key
def read_keys():
    f = open("./keys/bob_priv.pem", 'rb')
    bob_private_key = RSA.import_key(f.read())
    f.close()

    f = open("./keys/bob_public.pem", 'rb')
    bob_public_key = RSA.import_key(f.read())
    f.close()

    f = open("./keys/alice_public.pem", 'rb')
    alice_public_key = RSA.import_key(f.read())
    f.close()

    return bob_private_key, bob_public_key, alice_public_key

# Verify that a message hasn't been altered using HMAC-SHA 256
# Return true if the message is unaltered
# msg: string message to check
# mac: mac hash to check against the message
# key: mac secret key
def verify_message(msg, mac, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(msg.encode())

    try: 
        h.hexverify(mac)
        return True
    except:
        return False

def verify_message_num(message_num, expected_message_num):
    if message_num != expected_message_num:
        print("Messages Numbers Don't Line Up, Exiting!")
        exit(1)
        
# Decrypt an aes session key that was encrypted with your RSA public key
# Returns byte string session_key
# enc_session_key: string of the encrypted session key
# private_key: your RSA private key
def decrypt_session_key(enc_session_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key) 
    return session_key

# Decrypt an encrypted string using AES-CBC
# Returns decrypted string
# msg: the encrypted string, beginning with the IV for AES
# session key: the AES session key 
def decrypt(msg, session_key):
    try:
        iv = msg[0:24]
        ct = msg[24:]

        cipher = AES.new(session_key, AES.MODE_CBC, b64decode(iv))
        pt = unpad(cipher.decrypt(b64decode(ct)), AES.block_size)
        return pt
    except ValueError:
        return

def main():
    
    # Parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <port> <config>" % sys.argv[0])
        quit(1)

    # Setting the port
    port = sys.argv[1]
    config = sys.argv[2]

    # Set up encryption cnfiguration
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

    expected_message_num = 0

    # Open a socket
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind socket to ip and port
    listenfd.bind(('', int(port)))

    # Listen to socket
    listenfd.listen(1)

    # Accept connection
    (connfd, addr) = listenfd.accept()

    bob_private_key, bob_public_key, alice_public_key  = read_keys()

    # Load crypto tools if needed
    session_key = None
    mac_key = None
    if enc and mac:
        enc_session_key = connfd.recv(1024)
        session_key = decrypt_session_key(enc_session_key, bob_private_key)

        recieved_msg = connfd.recv(1024).decode()
        tag = recieved_msg[:64]
        encrypted_mac_key = recieved_msg[64:]
        mac_key = decrypt(encrypted_mac_key, session_key)

        print("Session Key: ", session_key, "\n")
        print("Encrypted Session Key: ", enc_session_key, "\n")
        print("Mac Key: ", mac_key, "\n")
        print("Encrypted Mac Key: ", encrypted_mac_key, "\n")
        print("Tag: ", tag, "\n")

    elif enc: 
        enc_session_key = connfd.recv(1024)
        session_key = decrypt_session_key(enc_session_key, bob_private_key)
        print("Session Key: ", session_key, "\n")
        print("Encrypted Session Key: ", enc_session_key, "\n")

    elif mac:
        mac_key = connfd.recv(1024)
        print("Mac Key: ", mac_key, "\n")
        
    # Message loop
    while(True):
        recieved_msg = connfd.recv(1024).decode()

        if enc and mac:
            message_number = int.from_bytes(recieved_msg[:4].encode(), "big")
            tag = recieved_msg[4:68]
            encrypted_message = recieved_msg[68:]

            if verify_message(encrypted_message, tag, mac_key):
                print("Message Is Authentic")
            else:
                print("Message Has Been Altered")

            decrypted_msg = decrypt(encrypted_message, session_key)
            verify_message_num(message_number, expected_message_num)
            expected_message_num += 1

            print("Message Number: ", message_number)
            print("Encrypted Message: ", encrypted_message)
            print("Tag: ", tag)
            print("Plain Message: ", decrypted_msg, "\n")

        elif enc:
            message_number = int.from_bytes(recieved_msg[:4].encode(), "big")
            encrypted_message = recieved_msg[4:]

            decrypted_msg = decrypt(encrypted_message, session_key)
            verify_message_num(message_number, expected_message_num)
            expected_message_num += 1
            
            print("Message Number: ", message_number)
            print("Encrypted Message: ", encrypted_message)
            print("Plain Message: ", decrypted_msg, "\n")

        elif mac:
            message_number = int.from_bytes(recieved_msg[:4].encode(), "big")
            tag = recieved_msg[4:68]
            message = recieved_msg[68:]
            
            if verify_message(message, tag, mac_key):
                print("\nMessage is authentic")
            else: 
                print("\nMessage has been altered")
            
            verify_message_num(message_number, expected_message_num)
            expected_message_num += 1

            print("Message Number: ", message_number)
            print("Tag: ", tag)
            print("Plain Message: ", message, "\n")

        else:
            message_number = int.from_bytes(recieved_msg[:4].encode(), "big")
            message = recieved_msg[4:]
            
            verify_message_num(message_number, expected_message_num)
            expected_message_num += 1
            
            print("Message Number: ", message_number)
            print("Plain Message: ", message, "\n")


    # Close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()
