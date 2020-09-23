import sys
import socket
from os import _exit as quit

def main():
    # parse arguments
    if len(sys.argv) != 3:
        print("usage: python3 %s <host> <port>" % sys.argv[0]);
        quit(1)
    host = sys.argv[1]
    port = sys.argv[2]

    # open a socket
    clientfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
