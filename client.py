import base64
import hashlib
import socket
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES

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

    # print('here')
    # step 1: A, B -->
    # print(UserName + '/' + recipient_name)
    client.send((UserName + '/' + recipient_name).encode())

    # step 2: {K_b, B}  \\K_t(-1) <--
    # serverRSA = PKCS1_OAEP.new(SERVER_RSA)

    # print(type(SERVER_RSA))
    message = b''
    for _ in range(10):
        message_enc = client.recv(2048)
        # en(message_enc))
        message += SERVER_RSA.decrypt(message_enc)
        # print(message)
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
    # print('bob_host', bob_host)
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
    # print('ALICE R_a\n', R_a)
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
    # print('ALICE R_b:', R_b)

    # step 7
    enc_message = bobRSA.encrypt(R_b)
    connection_to_Bob.send(enc_message)

    #################### create symmetric key
    R_a_sym = get_random_bytes(8)
    UserName_padding = string_padding(UserName)
    recipient_name_padding = string_padding(recipient_name)
    message = bytes(UserName_padding, 'ascii') + bytes(recipient_name_padding, 'ascii') + R_a_sym
    client.send(message)
    # print('SENDED MESSAGE:', message)

    # step 2
    message = b''
    for _ in range(9):
        message_enc = client.recv(128)
        # print('EN ', message_enc)
        # print(len(message_enc))
        message += userRSA.decrypt(message_enc)
        # print(message)
        client.send('ACK'.encode())
        # if b'stop' == message:
        #     break
    # print(message)
    R_a_sym_check = message[:8]
    bob_name_check = message[8:28]
    K_sym = message[28:156]

    en_part = message[156:]
    # print('en_part', en_part)
    dec_part = b''
    for i in range((len(en_part) // 128)):
        dec_part += bobRSA.decrypt(en_part[i * 128: (i + 1) * 128])
        # print('DEC', dec_part)
    K_sym_check = dec_part[:128]
    alice_name_check = dec_part[128:]

    # print(R_a_sym_check)
    # print(bob_name_check)
    # print(K_sym)
    # print(K_sym_check)
    # print(alice_name_check)

    # step 3
    message = K_sym + bytes(userName_padding, 'ascii')
    for i in range((len(message) // 64) + 1):
        c = bobRSA.encrypt(message[i * 64: (i + 1) * 64])
        connection_to_Bob.send(c)

    short_K_sym = K_sym[:16]
    message = connection_to_Bob.recv(1024)
    # print('REC MES', message)
    nonce = message[:16]
    tag = message[16:32]
    enc_R_b = message[32:]
    # print('nonce ', nonce)
    # print('tag ', tag)
    # print('short_K_sym ', short_K_sym)
    AEScipher = AES.new(short_K_sym, AES.MODE_GCM, nonce=nonce)
    plain_R_b = AEScipher.decrypt(enc_R_b)
    # print('plain_R_b', plain_R_b)

    try:
        AEScipher.verify(tag)
    except ValueError:
        print("Key incorrect or message corrupted")

    R_b_1 = plain_R_b[:-1]
    AEScipher = AES.new(short_K_sym, AES.MODE_GCM)
    nonce_to_Bob = AEScipher.nonce
    # print('nonce', nonce)
    # print('nonce_to_Bob', nonce_to_Bob)
    ciphertext, tag_to_bob = AEScipher.encrypt_and_digest(R_b_1)
    message = nonce_to_Bob + tag_to_bob + ciphertext
    connection_to_Bob.send(message)

    return short_K_sym, connection_to_Bob


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
    # print('sended mes:', message)
    server_connect.send(message.encode())

    # step 5
    message = b''
    for _ in range(10):
        message_enc = client.recv(2048)
        # print(len(message_enc))
        message += SERVER_RSA.decrypt(message_enc)
        # print(message)
        client.send('ACK'.encode())

    alice_name_check = message[:20].decode()
    alice_key = RSA.importKey(message[20:])
    # print(alice_name_check)
    # print(alice_name)
    if alice_name_check != alice_name:
        print('ERROR!!! INCORRECT MESSAGE FROM SERVER')
    # print('BOB SIDE alice_key:\n', alice_key)

    # print('alice_e: ', alice_e)
    # print('alice_n: ', alice_n)
    aliceRSA = PKCS1_OAEP.new(alice_key)
    # step 6
    R_b = get_random_bytes(8)
    # print('Bob R_b', R_b)
    message = R_a + R_b
    # enc_message = pow(int(message), alice_e, alice_n)
    message_enc = aliceRSA.encrypt(message)
    Client_to_Alice.send(message_enc)

    # step 7
    enc_message = Client_to_Alice.recv(2048)
    R_b_Alice = userRSA.decrypt(enc_message)
    if R_b_Alice != R_b:
        print('ERROR!!! Message spoofing in Alice side!')
    # print('OK!')

    # step 3
    dec_part = b''
    for i in range(3):
        message_enc = Client_to_Alice.recv(128)
        dec_part += userRSA.decrypt(message_enc)
        # print('DEC', dec_part)

    K_sym = dec_part[:128]
    alice_name_check2 = dec_part[128:]

    # print('K_sym\n', K_sym)
    # print('alice_name_check2\n', alice_name_check2)
    short_K_sym = K_sym[:16]
    # print('short_K_sym ', short_K_sym)
    AEScipher = AES.new(short_K_sym, AES.MODE_GCM)
    # print('BOB R_b', R_b)
    nonce = AEScipher.nonce
    enc_R_b, tag = AEScipher.encrypt_and_digest(R_b)
    # nonce 12, tag 16
    # print('nonce ', nonce)
    # print('tag ', tag)
    # print('enc_R_b ', enc_R_b)
    message = nonce + tag + enc_R_b
    Client_to_Alice.send(message)
    # print('message', message)

    message_enc = Client_to_Alice.recv(1024)
    nonce_from_Alice = message_enc[:16]
    tag = message_enc[16:32]
    ciphertext = message_enc[32:]
    AEScipher_from_Alice = AES.new(short_K_sym, AES.MODE_GCM, nonce=nonce_from_Alice)
    plain_R_b_1 = AEScipher_from_Alice.decrypt(ciphertext)

    try:
        AEScipher_from_Alice.verify(tag)
    except ValueError:
        print("Key incorrect or message corrupted")

    if R_b[:-1] != plain_R_b_1:
        print('ERRRRRRROR')
        sys.exit()

    print('OK2')
    return short_K_sym, Client_to_Alice


###############################

def messenger_for_alice(K_sym, connect_to_bob, userName):

    flagExit = False
    while not flagExit:
        message = input('(FROM CLIENT) ENTER YOUR MESSAGE: ')
        if message == 'quit':
            flagExit = True
        message = '(FROM ' + userName + ') ' + message

        AEScipher = AES.new(K_sym, AES.MODE_GCM)
        nonce_alice = AEScipher.nonce
        cipher, tag_alice = AEScipher.encrypt_and_digest(bytes(message, 'ascii'))
        message_enc = nonce_alice + tag_alice + cipher
        # print('FIRST mes', message_enc)
        # print('nonce ', nonce_alice)
        # print('tag ', tag_alice)
        # print('mes ', cipher)
        connect_to_bob.send(message_enc)
        #__________________________
        if not flagExit:
            cipher_from_bob = connect_to_bob.recv(2048)
            nonce_bob = cipher_from_bob[:16]
            tag_bob = cipher_from_bob[16:32]
            cipher_mb = cipher_from_bob[32:]
            AEScipher = AES.new(K_sym, AES.MODE_GCM, nonce=nonce_bob)
            message_from_bob = AEScipher.decrypt(cipher_mb).decode()
            try:
                AEScipher.verify(tag_bob)
            except ValueError:
                print("Key incorrect or message corrupted (Bob side)")

            print(message_from_bob)
            if message_from_bob.find('quit') != -1:
                flagExit = True


def messenger_for_bob(K_sym, connect_to_alice, userName):
    flagExit = False

    while not flagExit:
        cipher_to_alice = connect_to_alice.recv(2048)
        #print('SECOND mes', cipher_to_alice)

        nonce_alice = cipher_to_alice[:16]
        tag_alice = cipher_to_alice[16:32]
        cipher_ma = cipher_to_alice[32:]
        # print('nonce ', nonce_alice)
        # print('tag ', tag_alice)
        # print('mes ', cipher_ma)
        AEScipher = AES.new(K_sym, AES.MODE_GCM, nonce=nonce_alice)
        message_from_alice = AEScipher.decrypt(cipher_ma).decode()
        try:
            AEScipher.verify(tag_alice)
        except ValueError:
            print("Key incorrect or message corrupted (alice side)")
        if message_from_alice.find('quit') != -1:
            break
        print(message_from_alice)
        #_________________________
        message = input('(FROM CLIENT) ENTER YOUR MESSAGE: ')
        if message == 'quit':
            flagExit = True
        message = '(FROM ' + userName + ') ' + message

        AEScipher = AES.new(K_sym, AES.MODE_GCM)
        nonce_bob = AEScipher.nonce
        cipher, tag_bob = AEScipher.encrypt_and_digest(bytes(message, 'ascii'))
        connect_to_alice.send(nonce_bob + tag_bob + cipher)




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
            K_sym, connect_to_bob = initiate_connection(client, client_name)
            messenger_for_alice(K_sym, connect_to_bob, client_name)
            operation = 'quit'
        ###
        elif operation.lower() == 'wait connection' or operation.lower() == 'w':
            client.send(operation.lower()[0].encode())
            print(client.recv(1024).decode())
            K_sym, connect_to_alice = connect_to_user(client, userRSA, client_name)
            messenger_for_bob(K_sym, connect_to_alice, client_name)
            operation = 'quit'

        ###
        if operation.lower() == 'quit' or operation.lower() == 'q':
            client.send(operation.lower()[0].encode())
            break
        ###
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')
    client.close()
