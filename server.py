import socket
import os
import threading
import hashlib
from Crypto.Random import get_random_bytes
import ecdsa
from Crypto.PublicKey import RSA

# Create Socket (TCP) Connection
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
HOSTNAME = socket.gethostname()
HOST_IP = socket.gethostbyname(HOSTNAME)
PORT = 8082
ThreadCount = 0
MAX_CONNECTIONS = 5

UserName = []
RSAKeys = []
ServerRSAKeys = []
ClientRSAKeys = []
HostandPort = []

try:
    ServerSocket.bind((HOST_IP, PORT))
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(MAX_CONNECTIONS)


def create_user_profile(connection):
    flagName = False
    name = ''

    serverKeys = RSA.generate(2048)

    # n exchange
    clientKeyN = int.from_bytes(connection.recv(128), "big")
    connection.send(int(serverKeys.n).to_bytes(256, "big"))
    # e exchange
    clientKeyE = int.from_bytes(connection.recv(18), "big")
    connection.send(int(serverKeys.e).to_bytes(18, "big"))

    print('n\n', clientKeyN)
    print('e\n', clientKeyE)
    print('s_n\n', serverKeys.n)
    print('s_e\n', serverKeys.e)

    while not flagName:
        connection.send('(FROM SERVER) Enter your name/nickname: '.encode())
        name = connection.recv(1024).decode()
        if name not in UserName:
            flagName = True
            UserName.append(name)
            ServerRSAKeys.append(serverKeys)
            ClientRSAKeys.append((clientKeyN, clientKeyE))
            HostandPort.append(connection.getpeername())
            print('Host&Port:\n', connection.getpeername())
        connection.send(str(flagName).encode())

    return name


def choose_recipient(connection):
    flagRecipient = False

    A = connection.recv(1024).decode()  # Alice
    # connection.send('ACK'.encode())
    while not flagRecipient:
        connection.send('(FROM SERVER) Enter the name you want to communicate with: '.encode())
        B = connection.recv(1024).decode()  # Bob
        flagRecipient = B in UserName
        connection.send(str(flagRecipient).encode())

    # step 1: A, B
    connection.recv(1024).decode()

    # step 2
    userAIndex = UserName.index(A)
    userBIndex = UserName.index(B)
    # B[0] + n + e
    serverAKey = ServerRSAKeys[userAIndex]
    message = (str(ord(B[0]) % 2) +
               str(pow(ClientRSAKeys[userBIndex][0], serverAKey.d, serverAKey.n)) +
               str('/') + str(pow(ClientRSAKeys[userBIndex][1], serverAKey.d, serverAKey.n)))
    connection.send(message.encode())

    # step 3
    message = str(HostandPort[userBIndex][0])
    connection.send(message.encode())

    return B


##########################################################


def get_key_by_name(alice_name):
    userAIndex = UserName.index(alice_name)
    alice_e, alice_n = ClientRSAKeys[userAIndex]
    return alice_e, alice_n


def threaded_client(connection):
    first_client_name = create_user_profile(connection)
    ######
    operation = connection.recv(512).decode()
    while operation != 'q':
        if operation == 'l':
            connection.send(str(UserName).encode())
        elif operation == 'c':
            second_client_name = choose_recipient(connection)
        elif operation == 'w':
            connection.send('(FROM SERVER) Please, wait...\n'.encode())
            mes = connection.recv(2048).decode()
            print('mes:', mes)
            bob_name, alice_name = mes.split('/')
            alice_e, alice_n = get_key_by_name(alice_name)
            userBIndex = UserName.index(bob_name)
            serverBRSAKey = ServerRSAKeys[userBIndex]
            message = (str(ord(alice_name[0]) % 2) +
                       str(pow(alice_e, serverBRSAKey.d, serverBRSAKey.n)) +
                       str('/') + str(pow(alice_n, serverBRSAKey.d, serverBRSAKey.n)))
            connection.send(message.encode())
            print('alice_e: ', alice_e)
            print('alice_n: ', alice_n)

###########################################################


while True:
    Client, address = ServerSocket.accept()
    client_handler = threading.Thread(
        target=threaded_client,
        args=(Client,)
    )
    client_handler.start()
    ThreadCount += 1
    print('Connection Request: ' + str(ThreadCount))
    if ThreadCount == 0:
        break
ServerSocket.close()
