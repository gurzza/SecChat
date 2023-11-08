import base64
import socket
import os
import sys
import threading
import hashlib
from Crypto.Random import get_random_bytes
import ecdsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Create Socket (TCP) Connection
ServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
HOSTNAME = socket.gethostname()
HOST_IP = socket.gethostbyname(HOSTNAME)
PORT = 18082
ThreadCount = 0
MAX_CONNECTIONS = 5

UserName = []
RSAKeys = []
ServerRSA = []
ClientRSA = []
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

    serverKeysDER = serverKeys.exportKey('DER')
    clientKeyDER = connection.recv(2048)
    clientKey = RSA.importKey(clientKeyDER)
    connection.send(serverKeysDER)

    serverRSA = PKCS1_OAEP.new(serverKeys)
    clientRSA = PKCS1_OAEP.new(clientKey)

    while not flagName:
        connection.send('(FROM SERVER) Enter your name/nickname: '.encode())
        name = connection.recv(1024).decode()
        if name not in UserName:
            flagName = True
            UserName.append(name)
            ServerRSA.append(serverRSA)
            ClientRSA.append(clientRSA)
            HostandPort.append(connection.getpeername())
            print('Host&Port:\n', connection.getpeername())
            with open(name + 'key.txt', 'wb') as f:
                f.write(clientKeyDER)
        connection.send(str(flagName).encode())

    return name


def string_padding(string):
    return string + (20-len(string))*'0'

def string_without_padding(string):
    pos = string.find('0')
    return string[:pos]

def choose_recipient(connection):
    flagRecipient = False

    A = connection.recv(1024).decode()  # Alice
    while not flagRecipient:
        connection.send('(FROM SERVER) Enter the name you want to communicate with: '.encode())
        B = connection.recv(1024).decode()  # Bob
        flagRecipient = B in UserName
        connection.send(str(flagRecipient).encode())

    # step 1: A, B
    A_check, B_check = connection.recv(1024).decode().split('/')
    if A_check != A or B_check != B:
        print('Something wrong...')
        sys.exit()

    # step 2
    userAIndex = UserName.index(A)
    userBIndex = UserName.index(B)
    # B + key
    serverAliceRSA = ServerRSA[userAIndex]
    serverBobRSA = ServerRSA[userBIndex]
    clientAliceRSA = ClientRSA[userAIndex]
    clientBobRSA = ClientRSA[userBIndex]
    good_name = bytes(string_padding(B), 'ascii')
    with open(B + 'key.txt', 'rb') as f:
        bob_key = f.read()
    message = good_name + bob_key
    for i in range((len(message) // 64) + 1):
        c = serverAliceRSA.encrypt(message[i * 64: (i + 1) * 64])
        connection.send(c)
        if connection.recv(12).decode() != 'ACK':
            sys.exit()

    # step 3
    message = str(HostandPort[userBIndex][0])
    connection.send(message.encode())


    ########symmetric key
    message = connection.recv(1024)
    alice_name = string_without_padding(message[:20].decode())
    bob_name = string_without_padding(message[20:40].decode())
    R_a_sym = message[40:]
    if alice_name != A or bob_name != B:
        print('INCORRECT MESSSAGE FROM ALICE!!!')
        sys.exit()

    # step 2

    K = get_random_bytes(16)
    second_part = K + bytes(string_padding(alice_name), 'ascii')
    #print('K ', K)
    #print('R_a_sym ', R_a_sym)
    enc_part = b''
    for i in range((len(second_part) // 64) + 1):
        enc_part += clientBobRSA.encrypt(second_part[i * 64: (i + 1) * 64])

    message = R_a_sym + bytes(string_padding(bob_name), 'ascii') + K + enc_part


    for i in range((len(message) // 64) + 1):
        c = clientAliceRSA.encrypt(message[i * 64: (i + 1) * 64])

        connection.send(c)
        if connection.recv(12).decode() != 'ACK':
            sys.exit()
    return B


##########################################################



def threaded_client(connection):
    first_client_name = create_user_profile(connection)
    ######
    operation = connection.recv(512).decode()
    while operation != 'q':
        if operation == 'l':
            connection.send((" ".join(UserName)).encode())
        elif operation == 'c':
            second_client_name = choose_recipient(connection)
        elif operation == 'w':
            connection.send('(FROM SERVER) Please, wait...\n'.encode())
            mes = connection.recv(1024).decode()
            bob_name, alice_name_padding = mes.split('/')
            alice_name = string_without_padding(alice_name_padding)

            #step 5
            userBIndex = UserName.index(bob_name)
            serverBRSA = ServerRSA[userBIndex]
            with open(str(alice_name) + 'key.txt', 'rb') as f:
                alice_key = f.read()

            message = bytes(alice_name_padding, 'ascii') + alice_key

            for i in range((len(message) // 64) + 1):
                c = serverBRSA.encrypt(message[i * 64: (i + 1) * 64])
                connection.send(c)
                if connection.recv(12).decode() != 'ACK':
                    sys.exit()



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