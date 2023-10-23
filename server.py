import socket
import os
import threading
import hashlib
from Crypto.Random import get_random_bytes
import ecdsa

# Create Socket (TCP) Connection
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
HOSTNAME = socket.gethostname()
HOST_IP = socket.gethostbyname(HOSTNAME)
PORT = 8082
ThreadCount = 0
MAX_CONNECTIONS = 5

UserName = []
PK_DGST_KEYS = []
SERVER_PK_DGST = ''
SERVER_SK_DGST = ''

try:
    ServerSocket.bind((HOST_IP, PORT))
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(MAX_CONNECTIONS)


def create_user_profile(connection):
    flagName = False
    name = ''

    pk_key_client = connection.recv(1024).decode()
    # print('pk_key_client:\n', pk_key_client)
    while not flagName:
        connection.send('(FROM SERVER) Enter your name/nickname: '.encode())
        name = connection.recv(1024).decode()
        if name not in UserName:
            flagName = True
            UserName.append(name)
            PK_DGST_KEYS.append(pk_key_client)
        connection.send(str(flagName).encode())

    return name


def choose_recipient(connection):
    flagRecipient = False
    recipient_name = ''

    while not flagRecipient:
        connection.send('(FROM SERVER) Enter the name you want to communicate with: ')
        recipient_name = connection.recv(1024).decode()
        flagRecipient = recipient_name in UserName
        connection.send(str(flagRecipient).encode())

    return recipient_name


##########################################################
def key_exchange(connection, first_client_name, second_client_name):
    # sk
    s = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    # pk
    v = s.get_verifying_key()

    # msg = '1234'.encode()
    # dgst = s.sign(msg)
    # try:
    #     v.verify(dgst, '123'.encode())
    # except:
    #     print('ERROR!')


def threaded_client(connection):
    first_client_name = create_user_profile(connection)
    ######
    operation = connection.recv(512).decode()
    while operation != 'q':
        if operation == 'l':
            connection.send(str(UserName).encode())
        else:  # == 'c'
            second_client_name = choose_recipient(connection)
            key_exchange(connection, first_client_name, second_client_name)


###########################################################

SERVER_SK_DGST = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
SERVER_PK_DGST = SERVER_SK_DGST.get_verifying_key()

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
