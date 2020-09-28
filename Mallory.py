import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

# read in alice and bob's public keys
def read_keys():
    f = open("./keys/alice_public.pem", 'rb')
    alice_public = RSA.import_key(f.read())
    f.close()

    f = open("./keys/bob_public.pem", 'rb')
    bob_public = RSA.import_key(f.read())
    f.close()

    return (alice_public, bob_public)

# prompts user to alter messages and pass them on to their destination
# destination: the socket (fd) you want to send to
# msg: the body of the message (cipher or plaintext) string
# tag: the mac tag (None if mac = False)
# enc: is the message encrypted?
# mac: does the message have a mac tag?
# sends the altered message to destination
def alter_message(msg, tag, enc, mac):
    valid_behavior = False
    while not valid_behavior:
        valid_behavior = True
        behavior = input('would you like to change the message body? (y/n) ')
        if behavior == 'y':
            if enc:
                msg = input("Please enter new ciphertext: ")
            else:
                msg = input("Please enter a new message: ")
        elif behavior == 'n':
            msg = msg
        else:
            print("please input 'y' to alter the message or 'n' to send the original emssage")
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
                print("please input 'y' to alter the mac tag or 'n' to send the original tag")
                valid_behavior = False
        return (tag+msg).encode()
    else:
        return msg.encode()


def main():

    # parse arguments
    if len(sys.argv) != 5:
        print("usage: python3 %s <host> <listening_port> <writing_port> <config> % sys.argv[0]")
        quit(1)
    host = sys.argv[1]
    alice_port = sys.argv[2]
    bob_port = sys.argv[3]
    config = sys.argv[4]
 
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
        print("invalid configuration " + config + " valid configuration options: noCrypto, enc, mac, EncThenMac")
        quit(1)


    # open a socket to listen to alice
    alice_listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    alice_listenfd.bind(('', int(alice_port)))

    # listen to socket
    alice_listenfd.listen(1)
    
    # accept connection
    (alice_connfd, addr) = alice_listenfd.accept()
    print("Connected to Alice")


    # open a socket to broadcast to bob
    bob_clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to server
    bob_clientfd.connect((host, int(bob_port)))
    print("Connected to Bob \n")


    alice_public, bob_public = read_keys()

    # pass on keys (pretend you can't read them i guess?)
    if enc and mac:
        recieved_msg = alice_connfd.recv(1024) #probably need to do something here later
        bob_clientfd.send(recieved_msg)

        recieved_msg = alice_connfd.recv(1024) #probably need to do something here later
        bob_clientfd.send(recieved_msg)
        
    elif enc:
        recieved_msg = alice_connfd.recv(1024) #probably need to do something here later
        bob_clientfd.send(recieved_msg)
    
    elif mac:
        recieved_msg = alice_connfd.recv(1024) #probably need to do something here later
        bob_clientfd.send(recieved_msg)
    
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
            
            print("Message Number: ", int.from_bytes(message_number.encode(), "big"))
            print("Encrypted Message: " + message)
            print("Tag: " + tag + "\n")
            
        elif enc:
            message_number = recieved_msg[:4]
            message = recieved_msg[4:]
            
            print("Message Number: ", int.from_bytes(message_number.encode(), "big"))
            print("Encrypted Message: " + message + "\n")
            
        elif mac:
            message_number = recieved_msg[:4]
            tag = recieved_msg[4:68]
            message = recieved_msg[68:]
            
            print("Message Number: ", int.from_bytes(message_number.encode(), "big"))
            print("Message: " + message)
            print("Tag: " + tag + "\n")
            
        else:
            message_number = recieved_msg[:4]
            message = recieved_msg[4:]
            
            print("Message Number: ", int.from_bytes(message_number.encode(), "big"))
            print("Message: " + message + "\n")
            
        message_behavior = 0
        #what are you doing w the message
        while (message_behavior < 1) or (message_behavior > 3):
            # TODO: error handling
            message_behavior = int(input("Would you like to: \n 1: Pass this message to Bob without alteration \n 2: Edit this message \n 3: Delete this message? \n"))
            
            if message_behavior == 1: # send the message on w/o alteration
                print("Passing Message Along\n")
                # bob_clientfd.send(recieved_msg.encode())
                bob_clientfd.send(recieved_msg.encode())
                
            elif message_behavior == 2: #alter message
                altered_message = alter_message(message, tag, enc, mac)
                bob_clientfd.send(message_number.encode() + altered_message)
                
            elif message_behavior == 3: # do not send the message
                print("Dropping Message\n")
                
            else: #bad input 
                print("bad input, please enter 1, 2 or 3")

    # close connection
    alice_listenfd.close()
    bob_clientfd.close()

if __name__ == "__main__":
    main()
