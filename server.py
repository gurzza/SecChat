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

    # serverKeysPublicDER = serverKeys.publickey().exportKey('DER')
    serverKeysDER = serverKeys.exportKey('DER')
    # clientPublicKey = RSA.importKey(connection.recv(2048))
    clientKeyDER = connection.recv(2048)
    clientKey = RSA.importKey(clientKeyDER)
    # connection.send(serverKeysPublicDER)
    connection.send(serverKeysDER)
    # print('RECEIVED2:\n', clientPublicKey)

    serverRSA = PKCS1_OAEP.new(serverKeys)
    # clientRSADecryption = PKCS1_OAEP.new(clientPublicKey)
    clientRSA = PKCS1_OAEP.new(clientKey)
    # connection.recv(1024)
    # connection.send(serverRSA.encrypt(b'121'))

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
    #string = string.decode()
    pos = string.find('0')
    return string[:pos]

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
    print('(FROM ' + A + '):' + connection.recv(1024).decode())

    # step 2
    userAIndex = UserName.index(A)
    userBIndex = UserName.index(B)
    # B + key
    serverAliceRSA = ServerRSA[userAIndex]
    good_name = bytes(string_padding(B), 'ascii')
    with open(B + 'key.txt', 'rb') as f:
        bob_key = f.read()
    message = good_name + bob_key
    #aliceRSA = PKCS1_OAEP.new(serverRSA)
    #print('messaaa\n', message)
    for i in range((len(message) // 64) + 1):
        c = serverAliceRSA.encrypt(message[i * 64: (i + 1) * 64])
        print(len(c))
        connection.send(c)
        if connection.recv(12).decode() != 'ACK':
            sys.exit()
    #connection.send(serverAliceRSA.encrypt(b'stop'))

    #connection.send(serverAliceRSA.encrypt(message64))

    # step 3
    message = str(HostandPort[userBIndex][0])
    connection.send(message.encode())


    ########symmetric key
    message = connection.recv(1024).decode()
    alice_name, bob_name, R_a_sym = message.split('/')
    if alice_name != A or bob_name != B:
        print('INCORRECT MESSSAGE FROM ALICE!!!')
        sys.exit()

    # step 2

    K = get_random_bytes(256)
    first_part = K + bytes(alice_name, 'ascii')
    cipher = PKCS1_OAEP.new(key)
    # name length 20 bytes
    edited_name = bob_name + (20 - len(bob_name)) * 'a'
    message = bytes(R_a_sym, 'ascii') + bytes(edited_name, 'ascii') + K

    return B


##########################################################


# def get_key_by_name(alice_name):
#     userAIndex = UserName.index(alice_name)
#     alice_e, alice_n = ClientRSAKeys[userAIndex]
#     return alice_e, alice_n


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
            bob_name, alice_name_padding = mes.split('/')
            alice_name = string_without_padding(alice_name_padding)
            #alice_e, alice_n = get_key_by_name(alice_name)

            #step 5
            userBIndex = UserName.index(bob_name)
            serverBRSA = ServerRSA[userBIndex]
            with open(str(alice_name) + 'key.txt', 'rb') as f:
                alice_key = f.read()

            message = bytes(alice_name_padding, 'ascii') + alice_key
            #message_enc = serverBRSA(message)
            #print('SERVER SIDE alice_key:\n', alice_key)

            for i in range((len(message) // 64) + 1):
                c = serverBRSA.encrypt(message[i * 64: (i + 1) * 64])
                #print(len(c))
                connection.send(c)
                if connection.recv(12).decode() != 'ACK':
                    sys.exit()
            #connection.send(message_enc)
            # print("155555")
            # print('alice_e: ', alice_e)
            # print('alice_n: ', alice_n)


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
