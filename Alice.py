import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Signature import pss
from datetime import datetime

# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_pss.html

# Reads in alice's private key and bob's public key
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

# Generate an AES CBC cipher for the session
# Takes a RSA key
# Return a tuple containing
# enc_session_key, the AES key encrypted by the RSA key
# cipher_aes, the cipher object
def generate_session_key(public_key):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return (session_key, enc_session_key)

# Generate a random 256 bit string for use as a mac key
def generate_mac_key():
    return get_random_bytes(256)

# Return the hash for string msg using the sha256 HMAC with bytes of key
def generate_mac(msg, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(msg.encode())
    return h.hexdigest()
    
# Return a signature for a message
def generate_digital_signature(msg, key):
    hash = SHA256.new(msg)
    signature = pss.new(key).sign(hash)
    return signature
    
# Encrypt a message with an AES CBC cipher
# Takes a string msg to encode and the aes session key
# Return a string beginning with the initialization vector, followed by the encrypted message
def encrypt(msg, session_key):
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(msg, AES.block_size))
    iv = b64encode(cipher_aes.iv).decode('utf-8')
    cipher_text = b64encode(ct_bytes).decode('utf-8')
    result = iv + cipher_text

    return result

def main():

    # Parse arguments
    if len(sys.argv) != 4:
        print("usage: python3 %s <host> <port> <config> % sys.argv[0]")
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]
    config = sys.argv[3]
 
    # Set up encryption configuration
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

    message_number = 0

    # Open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server
    clientfd.connect((host, int(port)))
    print("Connected to server\n")


    alice_private_key, alice_public_key, bob_public_key = read_keys()

    # Load requested tools
    session_key = None
    enc_session_key = None
    mac_key = None
    enc_mac_key = None

    if enc and mac:
        session_key, enc_session_key = generate_session_key(bob_public_key)
        current_time = datetime.now()         # Use timedelta to test elapsed time t1 = t2%t3
        mac_key = generate_mac_key()
        enc_mac_key = encrypt(mac_key, session_key)
        
        message_to_sign = "bob".encode() + (current_time.strftime("%m/%d/%Y, %H:%M:%S")).encode() + enc_session_key + enc_mac_key.encode()
        digital_signature = generate_digital_signature(message_to_sign, alice_private_key)
        
        set_up_msg = message_to_sign + digital_signature
        clientfd.send(set_up_msg)
        
        print(len(current_time.strftime("%m/%d/%Y, %H:%M:%S").encode()))

        print("Message For: Bob\n")
        print("Time Sent: ", current_time.strftime("%m/%d/%Y, %H:%M:%S"), "\n")
        print("Session Key: ", session_key, "\n")
        print("Encrypted Session Key: ", enc_session_key, "\n")
        print("Mac Key: ", mac_key, "\n")
        print("Encrypted Mac Key: ", enc_mac_key, "\n")
        print("Digital Signature: ", digital_signature, "\n")

    elif enc:
        session_key, enc_session_key = generate_session_key(bob_public_key)
        current_time = datetime.now()
        
        message_to_sign = "bob".encode() + (current_time.strftime("%m/%d/%Y, %H:%M:%S")).encode() + enc_session_key
        digital_signature = generate_digital_signature(message_to_sign, alice_private_key)
        
        set_up_msg = message_to_sign + digital_signature
        clientfd.send(set_up_msg)

        print("Message For: Bob\n")
        print("Time Sent: ", current_time.strftime("%m/%d/%Y, %H:%M:%S"), "\n")
        print("Session Key: ", session_key, "\n")
        print("Encrypted Session Key: ", enc_session_key, "\n")
        print("Digital Signature: ", digital_signature, "\n")
        
    elif mac:
        mac_key = generate_mac_key()
        current_time = datetime.now()
        
        message_to_sign = "bob".encode() + (current_time.strftime("%m/%d/%Y, %H:%M:%S")).encode() + mac_key
        digital_signature = generate_digital_signature(message_to_sign, alice_private_key)
        
        set_up_msg = message_to_sign + digital_signature
        clientfd.send(set_up_msg)
        
        print(len(mac_key))
        
        print("Message For: Bob\n")
        print("Time Sent: ", current_time.strftime("%m/%d/%Y, %H:%M:%S"), "\n")
        print("Mac Key: ", mac_key, "\n")
        print("Digital Signature: ", digital_signature, "\n")

    # Message loop
    while(True):
        msg = input("Enter message: ")
        print()
        
        # Send encrypted message with mac tag
        if enc and mac:
            enc_message = encrypt(msg.encode(), session_key)
            tag = generate_mac(enc_message, mac_key)

            out_going_msg = message_number.to_bytes(4, byteorder='big') + (tag + enc_message).encode()
            clientfd.send(out_going_msg)

            print("Message Number: ", message_number)
            print("Plain Message: ", msg)
            print("Encrypted Message: ", enc_message)
            print("Tag: ", tag, "\n")
            
            message_number += 1
        
        # Send encrypted message with no tags
        elif enc:
            enc_message = encrypt(msg.encode(), session_key)
            
            out_going_msg = message_number.to_bytes(4, byteorder='big') + enc_message.encode()
            clientfd.send(out_going_msg)
            
            print("Message Number: ", message_number)
            print("Plain Message: ", msg)
            print("Encrypted Message: ", enc_message, "\n")
            
            message_number += 1

        # Send plaintext with mac tag
        elif mac: 
            tag = generate_mac(msg, mac_key)
            
            out_going_msg = message_number.to_bytes(4, byteorder='big') + (tag +  msg).encode()
            clientfd.send(out_going_msg)
            
            print("Message Number: ", message_number)
            print("Plain Message: ", msg)
            print("Tag: ", tag, "\n")
            
            message_number += 1
        
        # Send message in plaintext
        else:
            out_going_msg = message_number.to_bytes(4, byteorder='big') + msg.encode()
            clientfd.send(out_going_msg)
            
            print("Message Number: ", message_number)
            print("Plain Message: ", msg, "\n")
            
            message_number += 1

    # Close connection
    clientfd.close()

if __name__ == "__main__":
    main()


