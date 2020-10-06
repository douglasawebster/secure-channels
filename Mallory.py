import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

# Read in alice and bob's public keys
def read_keys():
    f = open("./keys/alice_public.pem", 'rb')
    alice_public = RSA.import_key(f.read())
    f.close()

    f = open("./keys/bob_public.pem", 'rb')
    bob_public = RSA.import_key(f.read())
    f.close()

    return (alice_public, bob_public)

# Prompts user to alter messages and pass them on to their destination
# destination: the socket (fd) you want to send to
# msg: the body of the message (cipher or plaintext) string
# tag: the mac tag (None if mac = False)
# enc: is the message encrypted?
# mac: does the message have a mac tag?
# Returns the altered message
def alter_message(msg, tag, enc, mac):
    valid_behavior = False
    while not valid_behavior:
        valid_behavior = True
        behavior = input('would you like to change the message body? (y/n) ')
        if behavior == 'y':
            if enc:
                iv = b64decode(msg[:24].encode('utf-8'))
                msg = b64decode(msg[24:].encode('utf-8'))
                print(iv)
                print()
                print(msg)
                print("the current iv is: " + b64encode(iv).decode('utf-8'))
                print("here are the blocks of the current ciphertext:")
                i = 0
                while (i+16<=len(msg)):
                    print ("i = " + str(i) + " len = "+ str(len(msg)))
                    print(b64encode(msg[i:i+16]).decode('utf-8'))
                    i+= 16
                print(msg[i:])
                iv = input("Please enter an IV: ")
                msg = input("Please enter new ciphertext: ")
            else:
                msg = input("Please enter a new message: ")
        elif behavior == 'n':
            msg = msg
        else:
            print("please input 'y' to alter the message or 'n' to send the original message")
            valid_behavior = False
    if mac:
        valid_behavior = False
        while not valid_behavior:
            valid_behavior = True
            behavior = input('would you like to change the mac tag? (y/n) ')
            if behavior == 'y':
                tag = input("Please enter the new mac tag: ")
            elif behavior =='n':
                tag = tag
            else:
                print("Please input 'y' to alter the mac tag or 'n' to send the original tag")
                valid_behavior = False
        return (tag+msg).encode()
    else:
        return msg.encode()
        
def alter_init_message(msg, enc, mac):
    altered_message = ""
    
    valid_behavior = False
    while not valid_behavior:
        valid_behavior = True
    
        message_for = msg[:3].decode()
        time_sent = msg[3:23].decode()
        
        behavior = input("Would you like to change who the message if for? (y/n)")
        if behavior == "y":
            message_for = input("Please enter a new name: ")
            altered_message += message_for
        elif behavior == "n":
            altered_message += message_for
        else:
            print("please input 'y' to alter the message or 'n' to send the original message")
            valid_behavior = False
            continue
        
        behavior = input("Would you like to change the time the message was sent? (y/n)")
        if behavior == "y":
            time_sent = input("Enter new time sent for message (%m/%d/%Y, %H:%M:%S)")
            altered_message += time_sent
        elif behavior == "n":
            altered_message += time_sent
        else:
            print("please input 'y' to alter the message or 'n' to send the original message")
            valid_behavior = False
            continue
            
        if enc and mac:
            enc_session_key = msg[23:279]
            enc_mac_key = msg[279:667].decode()
            digital_signature = msg[667:]
            
            behavior = input("Would you like to change the enc session key? (y/n)")
            if behavior == "y":
                enc_session_key = input("Enter new enc session key: ").encode()
            elif behavior == "n":
                enc_session_key = enc_session_key
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                
            behavior = input("Would you like to change the enc mac key? (y/n)")
            if behavior == "y":
                enc_mac_key = input("Enter new enc mac key: ")
            elif behavior == "n":
                enc_mac_key = enc_mac_key
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                
            behavior = input("Would you like to change the digital signature? (y/n)")
            if behavior == "y":
                digital_signature = input("Enter new digital signature: ").encode()
            elif behavior == "n":
                digital_signature = digital_signature
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                                
            return altered_message.encode() + enc_session_key + enc_mac_key.encode() + digital_signature
        elif enc:
            enc_session_key = msg[23:279]
            digital_signature = msg[279:]
            
            behavior = input("Would you like to change the enc session key? (y/n)")
            if behavior == "y":
                enc_session_key = input("Enter new enc session key: ").encode()
            elif behavior == "n":
                enc_session_key = enc_session_key
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                
            behavior = input("Would you like to change the digital signature? (y/n)")
            if behavior == "y":
                digital_signature = input("Enter new digital signature: ").encode()
            elif behavior == "n":
                digital_signature = digital_signature
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                                
            return altered_message.encode() + enc_session_key + digital_signature
        elif mac:
            mac_key = msg[23:279]
            digital_signature = msg[279:]
        
            behavior = input("Would you like to change the mac key? (y/n)")
            if behavior == "y":
                mac_key = input("Enter new mac key: ").encode()
            elif behavior == "n":
                mac_key = mac_key
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                
            behavior = input("Would you like to change the digital signature? (y/n)")
            if behavior == "y":
                digital_signature = input("Enter new digital signature: ").encode()
            elif behavior == "n":
                digital_signature = digital_signature
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
                                
            return altered_message.encode() + mac_key + digital_signature
                
def main():

    # Parse arguments
    if len(sys.argv) != 5:
        print("usage: python3 %s <host> <listening_port> <writing_port> <config> % sys.argv[0]")
        quit(1)
    host = sys.argv[1]
    alice_port = sys.argv[2]
    bob_port = sys.argv[3]
    config = sys.argv[4]
 
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
        print("invalid configuration " + config + " valid configuration options: noCrypto, enc, mac, EncThenMac")
        quit(1)

    # Open a socket to listen to alice
    alice_listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind socket to ip and port
    alice_listenfd.bind(('', int(alice_port)))

    # Listen to socket
    alice_listenfd.listen(1)
    
    # Accept connection
    (alice_connfd, addr) = alice_listenfd.accept()
    print("Connected to Alice")

    # Open a socket to broadcast to bob
    bob_clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server
    bob_clientfd.connect((host, int(bob_port)))
    print("Connected to Bob\n")

    alice_public, bob_public = read_keys()
    
    
    stored_msg = None
    stored_tag = None
    # Pass on keys
    if enc or mac:
        recieved_msg = alice_connfd.recv(1024)

        init_message_for_bob = None
        
        valid_behavior = False
        while not valid_behavior:
            valid_behavior = True

            behavior = input("Would you like to alter the init message? (y/n)")

            if behavior == "y":
                init_message_for_bob = alter_init_message(recieved_msg, enc, mac)
            elif behavior == "n":
                init_message_for_bob = recieved_msg
            else:
                print("please input 'y' to alter the message or 'n' to send the original message")
                valid_behavior = False
                continue
            
        bob_clientfd.send(init_message_for_bob)
    
    # message loop
    while(True):
        recieved_msg = alice_connfd.recv(1024).decode()
        
        # TODO determine what should be printed here in different cases
        message_number = None
        message = None
        tag = None
        
        if enc and mac:
            message_number = recieved_msg[:4]
            tag = recieved_msg[4:68]
            message = recieved_msg[68:]
            
        elif enc:
            message_number = recieved_msg[:4]
            message = recieved_msg[4:]
            
        elif mac:
            message_number = recieved_msg[:4]
            tag = recieved_msg[4:68]
            message = recieved_msg[68:]
            
        else:
            message_number = recieved_msg[:4]
            message = recieved_msg[4:]
            
        if message_number is not None: print("Message Number: ", int.from_bytes(message_number.encode(), "big"))
        if message is not None: print("Message: " + message)
        if tag is not None: print("Tag: " + tag + "\n")
            
        message_behavior = 0
        # What are you doing w the message
        while (message_behavior < 1) or (message_behavior > 5):
            message_behavior = int(input("Would you like to: \n 1: Pass this message to Bob without alteration \n 2: Edit this message \n 3: Delete this message? \n 4: Store this message \n 5: Replay the stored message \n"))
            
            if message_behavior == 1: # Send message as is
                print("Passing Message Along\n")
                bob_clientfd.send(recieved_msg.encode())
                
            elif message_behavior == 2: # Alter message
                altered_message = alter_message(message, tag, enc, mac)
                bob_clientfd.send(message_number.encode() + altered_message)
                
            elif message_behavior == 3: # Drop message
                print("Dropping Message\n")

            elif message_behavior == 4:
                print("Current stored message is: "+ str(stored_msg) + "\n would you like to overwrite it with " + message)
                behavior = input ("replace stored message? y/n \n")
                if behavior == 'y':
                    stored_msg = message
                    if mac:
                        stored_tag = tag
                    print("new stored message is : "+ stored_msg )
                elif behavior == 'n':
                    print("keeping " + stored_msg + "stored \n")
                else:
                    print("please enter y(es) or n(o)")
                message_behavior = 0
                print("what would you like to do with message " + message)

            elif message_behavior == 5:
                if stored_msg == None:
                    print("You have no message stored! Try something else")
                    message_behavior = 0
                else:
                    print("Current stored message is " + str(stored_msg) + "\n would you like to send it to Bob?\n")
                    behavior = input("send stored message? y/n \n")
                    if behavior == 'y':
                        print("replaying")
                        if mac:
                            bob_clientfd.send(message_number.encode() + stored_tag.encode() +stored_msg.encode())
                        else:
                            bob_clientfd.send(message_number.encode() + stored_msg.encode())
            else: # Bad input
                print("Bad input, please enter a number, 1-5")

    # Close connection
    alice_listenfd.close()
    bob_clientfd.close()

if __name__ == "__main__":
    main()
