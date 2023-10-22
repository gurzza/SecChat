import socket
import os
import threading
import hashlib
from Crypto.Random import get_random_bytes

UserName = []


def create_user_name(connection):
    flagName = False

    while not flagName:
        connection.send('(FROM SERVER) Enter your name/nickname: '.encode())
        name = connection.recv(1024).decode()
        if not name in UserName:
            flagName = True
            UserName.append(name)


def choose_recipient(connection):
    connection.send('(FROM SERVER) Enter the name you want to communicate with: ')


def threaded_client(connection):
    create_user_name(connection)
    ######
    operation = connection.recv(1024).decode()



    #choose_recipient(connection)


    client_data = connection.recv(1024).decode()
    while client_data.upper() != 'QUIT' and client_data.upper() != 'Q':
        client_data = connection.recv(2048).decode()


#
#
#


if __name__ == "__main__":
    # Create Socket (TCP) Connection
    ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    HOSTNAME = socket.gethostname()
    HOST_IP = socket.gethostbyname(HOSTNAME)
    PORT = 8081
    ThreadCount = 0
    MAX_CONNECTIONS = 5

    try:
        ServerSocket.bind((HOST_IP, PORT))
    except socket.error as e:
        print(str(e))

    print('Waiting for a Connection..')
    ServerSocket.listen(5)

    while True:
        Client, address = ServerSocket.accept()

        client_handler = threading.Thread(
            target=threaded_client,
            args=Client
        )
        client_handler.start()
        print('Connection Request: ' + str(ThreadCount))
        if ThreadCount == 0:
            break
    ServerSocket.close()
