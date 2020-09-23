import sys
import socket
from os import _exit as quit

def main():
    # parse arguments
    if len(sys.argv) != 2:
        print("usage: python3 %s <port>" % sys.argv[0])
        quit(1)
    port = sys.argv[1]
    
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
