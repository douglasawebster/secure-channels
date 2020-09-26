import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode

# read in alice and bob's public keys
def read_keys():
    f = open('./keys/alice_public.pem', 'rb')
    alice_public = RSA.import_key(f.read())
    f.close()

    f = open('./keys/bob_public.pem', 'rb')
    bob_public = RSA.import_key(f.read())
    f.close()

    return (alice_public, bob_public)

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
        print("invalid configuration "+ config + " valid configuration options: noCrypto, enc, mac, EncThenMac")
        quit(1)


    # open a socket to listen to alice
    alice_listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    alice_listenfd.bind(('', int(alice_port)))

    # listen to socket
    alice_listenfd.listen(1)
    
    print("Connecting to Alice")
    # accept connection
    (alice_connfd, addr) = alice_listenfd.accept()

    # open a socket to broadcast to bob
    bob_clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Connecting to Bob")
    # connect to server
    bob_clientfd.connect((host, int(bob_port)))

    alice_public, bob_public = read_keys()

    # pass on keys (pretend you can't read them i guess?)
    if enc:
        recieved_msg = alice_connfd.recv(1024) #probably need to do something here later
        bob_clientfd.send(recieved_msg)

    if mac:
        recieved_msg = alice_connfd.recv(1024)
        bob_clientfd.send(recieved_msg)
    
    # message loop
    while(True):
        # recieved_msg = alice_connfd.recv(1024).decode()
        recieved_msg = alice_connfd.recv(1024)
        #TODO determine what should be printed here in different cases

        message_behavior = 0
        #what are you doing w the message
        while (message_behavior < 1) or (message_behavior > 3):
            # TODO: error handling

            print(recieved_msg)
            message_behavior = int(input("Would you like to: \n 1: Pass this message to Bob \n 2: Edit this message \n 3: Delete this message? \n"))
            
            if message_behavior == 1: # send the message on w/o alteration
                print("passing the message on")
                # bob_clientfd.send(recieved_msg.encode())
                print(recieved_msg)
                bob_clientfd.send(recieved_msg)
            elif message_behavior == 2: #alter message
                #TODO: implement alter
                print("alter message (not implemented")
            elif message_behavior == 3: # do not send the message
                print("message dropped")
            else: #bad input TODO:write better instructions
                print("bad input")

            
            


#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    alice_listenfd.close()
    bob_clientfd.close()

if __name__ == "__main__":
    main()
