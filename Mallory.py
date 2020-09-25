import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA

def read_keys():
    global alice_public, bob_public
    f = open('./keys/alice_public.pem', 'rb')
    alice_public = RSA.import_key(f.read())
    f.close()

    f = open('./keys/bob_public.pem', 'rb')
    bob_public = RSA.import_key(f.read())
    f.close()

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

    # load crypto tools if needed
    if enc:
        read_keys()

    # open a socket to listen to alice
    alice_listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    alice_listenfd.bind(('', int(alice_port)))

    # listen to socket
    alice_listenfd.listen(1)
    
    print("connect to alice")
    # accept connection
    (alice_connfd, addr) = alice_listenfd.accept()

    print("connected")
    # open a socket to broadcast to bob
    bob_clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("connect to bob")
    # connect to server
    bob_clientfd.connect((host, int(bob_port)))

    # message loop
    print("connected")
    while(True):
        msg_recieved = alice_connfd.recv(1024).decode()
        print("Received from alice: %s" % msg_recieved)
        msg_to_send = input("Enter message for server: ")
        bob_clientfd.send(msg_to_send.encode())

#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    alice_listenfd.close()
    bob_clientfd.close()

if __name__ == "__main__":
    main()
