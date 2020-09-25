import sys
import socket
from os import _exit as quit
from Crypto.PublicKey import RSA

def read_keys():
    global public_key, private_key
    f = open('./keys/bob_priv.pem', 'rb')
    private_key = RSA.import_key(f.read())
    f.close()

    f = open('./keys/bob_public.pem', 'rb')
    public_key = RSA.import_key(f.read())
    f.close()

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

    # load crypto tools if needed
    if enc: 
        read_keys()
    if mac:
        read_mac()

    # open a socket
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind socket to ip and port
    listenfd.bind(('', int(port)))

    # listen to socket
    listenfd.listen(1)

    # accept connection
    (connfd, addr) = listenfd.accept()

    # message loop
    while(True):
        msg = connfd.recv(1024).decode()
        if(detect_shennanigans(msg)):
            print("the following message has been altered: %s" % msg)
        else:
            print("Received from client: %s" % msg)

#        # You don't need to send a response for this assignment
#        # but if you wanted to you'd do something like this
#        msg = input("Enter message for client: ")
#        connfd.send(msg.encode())

    # close connection
    connfd.close()
    listenfd.close()


if __name__ == "__main__":
    main()
