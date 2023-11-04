import base64
import hashlib
import socket
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

SERVER_RSA = None
# CLIENT_RSA_KEYS = []
PORT_FOR_BOB = 15_000


def create_my_name(sc):
    flagName = False
    name = ''
    global SERVER_RSA
    userKeys = RSA.generate(1024)

    # userKeysPublicDER = userKeys.publickey().exportKey('DER')
    userKeysDER = userKeys.exportKey('DER')
    # sc.send(userKeysPublicDER)
    sc.send(userKeysDER)
    key = sc.recv(2048)
    serverPublicKey = RSA.importKey(key)
    userRSA = PKCS1_OAEP.new(userKeys)
    SERVER_RSA = PKCS1_OAEP.new(serverPublicKey)
    # sc.send('aCK'.encode())
    # message = sc.recv(2048)
    # print(SERVER_RSA.decrypt(message))

    while not flagName:
        name = input(sc.recv(1024).decode())
        sc.send(name.encode())
        flagName = (sc.recv(1024).decode() == 'True')
    return name, userRSA


def print_operations():
    print("Options:")
    print("\t Enter 'quit' or 'q' to exit")
    print("\t Enter 'list' or 'l' to list established secure users")
    print("\t Enter 'connect' or 'c' to start conversation")
    print("\t Enter 'wait connection' or 'w' to wait connection")


def print_user_list(client):
    UserName = client.recv(2048).decode()
    # print('Connected users:\n', ', '.join(UserName))
    print('Connected users:\n', UserName)


def string_padding(string):
    return string + (20 - len(string)) * '0'


def initiate_connection(client, UserName):
    flagRecipient = False
    recipient_name = ''

    client.send(UserName.encode())
    # client.recv(1024).decode()
    while not flagRecipient:
        recipient_name = input(client.recv(1024).decode())
        client.send(recipient_name.encode())
        flagRecipient = (client.recv(1024).decode() == 'True')

    print('here')
    # step 1: A, B -->
    print(UserName + '/' + recipient_name)
    client.send((UserName + '/' + recipient_name).encode())

    # step 2: {K_b, B}  \\K_t(-1) <--
    # serverRSA = PKCS1_OAEP.new(SERVER_RSA)

    # print(type(SERVER_RSA))
    message = b''
    for _ in range(10):
        message_enc = client.recv(2048)
        #en(message_enc))
        message += SERVER_RSA.decrypt(message_enc)
        #print(message)
        client.send('ACK'.encode())
        # if b'stop' == message:
        #     break
    bob_name = message[:20].decode()
    bob_key = RSA.importKey(message[20:])

    # print('bob_name: ', bob_name)
    # print('bob_key: ', bob_key)

    recipient_name_name_padding = string_padding(recipient_name)
    if recipient_name_name_padding != bob_name:
        print('ERROR!!! Message substitution has been occurred...')
        sys.exit()
    # n_end = message.find('/')
    # bob_n = pow(int(message[1: n_end]), SERVER_RSA_E, SERVER_RSA_N)
    # bob_e = pow(int(message[n_end + 1:]), SERVER_RSA_E, SERVER_RSA_N)

    # step 3
    bob_host = client.recv(1024).decode()
    print('bob_host', bob_host)
    # create connection
    connection_to_Bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_to_Bob.connect((bob_host, PORT_FOR_BOB))
    # T + {Ra, A}
    # connection_to_Bob.send(UserName.encode())  # send my name
    # connection_to_Bob.recv(1024)  # ACK
    # message = str(int(client.getpeername()[0][0]) % 2)
    # R_a = int.from_bytes(get_random_bytes(8), "big")
    # print('ALICE R_a:', R_a)
    # message_to_enc = str(ord(UserName[0]) % 2) + str(R_a)
    # enc_message = pow(int(message_to_enc), bob_e, bob_n)
    # message_to_send = message + str(enc_message)


    bobRSA = PKCS1_OAEP.new(bob_key)
    R_a = get_random_bytes(8)
    print('ALICE R_a\n', R_a)
    T = bytes(str(client.getpeername()[1]), 'ascii')  # get server port
    userName_padding = string_padding(UserName)
    second_part = R_a + bytes(userName_padding, 'ascii')
    enc_part = bobRSA.encrypt(second_part)
    connection_to_Bob.send(T)
    if connection_to_Bob.recv(12).decode() != 'ACK':
        sys.exit()
    connection_to_Bob.send(enc_part)

    # step 6
    enc_message = connection_to_Bob.recv(2048)
    message = userRSA.decrypt(enc_message)
    R_a_Bob = message[:8]
    if R_a_Bob != R_a:
        print('ERROR!!! Message spoofing!')
        sys.exit()
    R_b = message[8:]
    print('ALICE R_b:', R_b)

    # step 7
    enc_message = bobRSA.encrypt(R_b)
    connection_to_Bob.send(enc_message)

    #################### create symmetric key
    R_a_sym = get_random_bytes(8)
    message = UserName + '/' + recipient_name + '/' + str(R_a_sym)
    client.send(message.encode())
    print('SENDED MESSAGE:', message)
    return recipient_name


####################################


def connect_to_user(server_connect, userRSA, myUserName):  # bob side
    clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    HOSTNAME = socket.gethostname()
    HOST_IP = socket.gethostbyname(HOSTNAME)
    # PORT = 10_000
    try:
        clientSocket.bind((HOST_IP, PORT_FOR_BOB))
    except socket.error as e:
        print(str(e))
    clientSocket.listen(1)
    Client_to_Alice, address = clientSocket.accept()
    ####
    # step 3
    serverPort_checker = Client_to_Alice.recv(1024).decode()
    Client_to_Alice.send('ACK'.encode())
    message_enc = Client_to_Alice.recv(1024)
    message = userRSA.decrypt(message_enc)
    R_a = message[:8]
    alice_name = message[8:].decode()
    # print('BOB SIDE:\n')
    # print('R_a:\n', R_a)
    # print('ALICE_NAME:\n', alice_name)


    # print('Bob R_a:', R_a)

    # step 4
    # alice_ip, alice_port = Client_to_Alice.getpeername()
    # print('port_type:', type(alice_port))
    message = myUserName + '/' + alice_name
    #print('sended mes:', message)
    server_connect.send(message.encode())

    # step 5
    message = b''
    for _ in range(10):
        message_enc = client.recv(2048)
        #print(len(message_enc))
        message += SERVER_RSA.decrypt(message_enc)
        # print(message)
        client.send('ACK'.encode())

    alice_name_check = message[:20].decode()
    alice_key = RSA.importKey(message[20:])
    #print(alice_name_check)
    #print(alice_name)
    if alice_name_check != alice_name:
        print('ERROR!!! INCORRECT MESSAGE FROM SERVER')
    #print('BOB SIDE alice_key:\n', alice_key)

    # print('alice_e: ', alice_e)
    # print('alice_n: ', alice_n)
    aliceRSA = PKCS1_OAEP.new(alice_key)
    # step 6
    R_b = get_random_bytes(8)
    print('Bob R_b', R_b)
    message = R_a + R_b
    #enc_message = pow(int(message), alice_e, alice_n)
    message_enc = aliceRSA.encrypt(message)
    Client_to_Alice.send(message_enc)

    # step 7
    enc_message = Client_to_Alice.recv(2048)
    R_b_Alice = userRSA.decrypt(enc_message)
    if R_b_Alice != R_b:
        print('ERROR!!! Message spoofing in Alice side!')
    print('OK!')

###############################

if __name__ == '__main__':
    # create connection
    SERVER_NAME = 'DESKTOP-7FRD9J8'
    SERVER_IP = socket.gethostbyname(SERVER_NAME)
    PORT = 18082

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # remove or keep try-except?
    # try:
    client.connect((SERVER_IP, PORT))
    # except:
    #   sys.exit()
    #########

    # log in

    client_name, userRSA = create_my_name(client)
    print('Welcome, ', client_name, '\n')
    #########

    operation = ''
    while 1:
        print_operations()
        operation = input()
        if operation.lower() == 'list' or operation.lower() == 'l':
            client.send(operation.lower()[0].encode())
            # UserName = client.recv(2048).decode()
            print_user_list(client)
        ###
        elif operation.lower() == 'connect' or operation.lower() == 'c':
            client.send(operation.lower()[0].encode())
            rec_name = initiate_connection(client, client_name)
        ###
        elif operation.lower() == 'wait connection' or operation.lower() == 'w':
            client.send(operation.lower()[0].encode())
            print(client.recv(1024).decode())
            connect_to_user(client, userRSA, client_name)

        ###
        elif operation.lower() == 'quit' or operation.lower() == 'q':
            client.send(operation.lower()[0].encode())
            break
        ###
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')
    client.close()
