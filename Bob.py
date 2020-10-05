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
from datetime import datetime
from Crypto.Signature import pss

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
    return message_num == expected_message_num

def verify_digital_signature(msg, signature, key):
    hash = SHA256.new(msg)
    verifier = pss.new(key)
    
    try:
        verifier.verify(hash, signature)
        return True
    except:
        return False
        
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
        iv = msg[:24]
        ct = msg[24:]

        cipher = AES.new(session_key, AES.MODE_CBC, b64decode(iv))
        pt = unpad(cipher.decrypt(b64decode(ct)), AES.block_size)
        return pt
    except ValueError:
        return "decryption failled, message corrupted"

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
    enc_session_key = None
    mac_key = None
    enc_mac_key = None
    digital_signature = None

    initial_msg = None
    msg_for = None
    time_sent_str = None
    signed_msg = None
    
    if enc or mac:
        initial_msg = connfd.recv(1024)
        msg_for = initial_msg[:3].decode()
        time_sent_str = initial_msg[3:23].decode()
        
        signed_msg = msg_for.encode() + time_sent_str.encode()
    
    if enc and mac:
        enc_session_key = initial_msg[23:279]
        enc_mac_key = initial_msg[279:667].decode()
        digital_signature = initial_msg[667:]
                
        session_key = decrypt_session_key(enc_session_key, bob_private_key)
        mac_key = decrypt(enc_mac_key, session_key)
        
        signed_msg += enc_session_key + enc_mac_key.encode()

    elif enc:
        enc_session_key = initial_msg[23:279]
        digital_signature = initial_msg[279:]

        session_key = decrypt_session_key(enc_session_key, bob_private_key)

        signed_msg += enc_session_key

    elif mac:
        mac_key = initial_msg[23:279]
        digital_signature = initial_msg[279:]
        
        signed_msg = msg_for.encode() + time_sent_str.encode() + mac_key
        
    if enc or mac:
        if verify_digital_signature(signed_msg, digital_signature, alice_public_key):
            print("The Signature Is Authentic.\n")
        else:
            print("The Signature Is Not Authentic.\n")
            print("Terminating Connection!")
            exit(1)
            
        time_sent = datetime.strptime(time_sent_str, "%m/%d/%Y, %H:%M:%S")
        current_time = datetime.now()
        
        time_delta = current_time - time_sent
        if time_delta.seconds > 120:
            print("Too Much Time Has Elapsed!")
            print("Terminating Connection!")
            exit(1)
        
        print("Message For: ", msg_for, "\n")
        print("Time Sent: ", time_sent_str, "\n")
        print("Time Recieved: ", current_time, "\n")
        if session_key is not None: print("Session Key: ", session_key, "\n")
        if enc_session_key is not None: print("Encrypted Session Key: ", enc_session_key, "\n")
        if mac_key is not None: print("Mac Key: ", mac_key, "\n")
        if enc_mac_key is not None: print("Encrypted Mac Key: ", enc_mac_key, "\n")
        if digital_signature is not None: print("Digital Signature: ", digital_signature, "\n")

    print('recieving')
    # Message loop
    while(True):
        recieved_msg = connfd.recv(1024).decode()
        print('recieved:' + recieved_msg)
        message = None
        encrypted_message = None
        tag = None
        decrypted_msg = None
        
        message_number = int.from_bytes(recieved_msg[:4].encode(), "big")

        if enc and mac:
            tag = recieved_msg[4:68]
            encrypted_message = recieved_msg[68:]
            message = decrypt(encrypted_message, session_key)

        elif enc:
            encrypted_message = recieved_msg[4:]
            message = decrypt(encrypted_message, session_key)

        elif mac:
            tag = recieved_msg[4:68]
            message = recieved_msg[68:]

        else:
            message = recieved_msg[4:]
            
            
        if not verify_message_num(message_number, expected_message_num):
            print("Messages Numbers Don't Line Up!")
            print("Terminating Connection!")
            exit(1)
        else:
            expected_message_num += 1

        if mac:
            message_to_verify = encrypted_message if enc else message
            if verify_message(message_to_verify, tag, mac_key):
                print("Message Is Authentic")
            else:
                print("Message Has Been Altered")
                print("Terminating Connection!")
                exit(1)
        
        print("Message Number: ", message_number)
        if encrypted_message is not None: print("Encrypted Message: ", encrypted_message)
        if tag is not None: print("Tag: ", tag)
        print("Plain Message: ", message, "\n")

    # Close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()
