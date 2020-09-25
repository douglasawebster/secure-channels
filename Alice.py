import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA



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

    # load crypto tools if needed
    if enc:
        read_keys()
    if mac:
        read_mac()

    # open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("connecting to server")
    # connect to server
    clientfd.connect((host, int(port)))

    # message loop
    while(True):
        msg = input("Enter message for server: ")
        clientfd.send(msg.encode())

#        # You don't need to receive for this assignment, but if you wanted to
#        # you would use something like this
#        msg = clientfd.recv(1024).decode()
#        print("Received from server: %s" % msg)

    # close connection
    clientfd.close()

if __name__ == "__main__":
    main()


