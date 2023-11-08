import base64
import hashlib
import socket
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES

SERVER_RSA = None
PORT_FOR_BOB = 15_000


def create_my_name(sc):
    flagName = False
    name = ''
    global SERVER_RSA
    userKeys = RSA.generate(1024)

    userKeysDER = userKeys.exportKey('DER')
    sc.send(userKeysDER)
    key = sc.recv(2048)
    serverPublicKey = RSA.importKey(key)
    userRSA = PKCS1_OAEP.new(userKeys)
    SERVER_RSA = PKCS1_OAEP.new(serverPublicKey)

    while not flagName:
        name = input(sc.recv(1024).decode())
        sc.send(name.encode())
        flagName = (sc.recv(1024).decode() == 'True')
    return name, userRSA


def print_operations():
    print("Options:")
    print("\t Enter 'quit' or 'q' to exit")
    #print("\t Enter 'list' or 'l' to list established secure users")
    print("\t Enter 'connect' or 'c' to start conversation")
    print("\t Enter 'wait connection' or 'w' to wait connection")


def print_user_list(client):
    UserName = client.recv(1024).decode('utf-8')
    print('Connected users:\n', UserName)


def string_padding(string):
    return string + (20 - len(string)) * '0'


def initiate_connection(client, UserName):
    flagRecipient = False
    recipient_name = ''

    client.send(UserName.encode())
    while not flagRecipient:
        recipient_name = input(client.recv(1024).decode())
        client.send(recipient_name.encode())
        flagRecipient = (client.recv(1024).decode() == 'True')

    # step 1: A, B -->
    client.send((UserName + '/' + recipient_name).encode())

    # step 2: {K_b, B}  \\K_t(-1) <--

    message = b''
    for _ in range(10):
        message_enc = client.recv(2048)
        message += SERVER_RSA.decrypt(message_enc)
        client.send('ACK'.encode())
    bob_name = message[:20].decode()
    bob_key = RSA.importKey(message[20:])

    recipient_name_name_padding = string_padding(recipient_name)
    if recipient_name_name_padding != bob_name:
        print('ERROR!!! Message substitution has been occurred...')
        sys.exit()

    # step 3
    bob_host = client.recv(1024).decode()
    connection_to_Bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_to_Bob.connect((bob_host, PORT_FOR_BOB))

    bobRSA = PKCS1_OAEP.new(bob_key)
    R_a = get_random_bytes(8)
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

    # step 7
    enc_message = bobRSA.encrypt(R_b)
    connection_to_Bob.send(enc_message)

    #################### create symmetric key
    R_a_sym = get_random_bytes(8)
    UserName_padding = string_padding(UserName)
    recipient_name_padding = string_padding(recipient_name)
    message = bytes(UserName_padding, 'ascii') + bytes(recipient_name_padding, 'ascii') + R_a_sym
    client.send(message)

    # step 2
    message = b''
    for _ in range(3):
        message_enc = client.recv(128)
        message += userRSA.decrypt(message_enc)
        client.send('ACK'.encode())
    # print('here2')
    # print(message)
    R_a_sym_check = message[:8]
    bob_name_check = message[8:28]
    K_sym = message[28:44]

    en_part = message[44:]
    dec_part = b''
    for i in range((len(en_part) // 128)):
        dec_part += bobRSA.decrypt(en_part[i * 128: (i + 1) * 128])
    K_sym_check = dec_part[:16]
    alice_name_check = dec_part[16:]

    if K_sym_check != K_sym:
        print('ERROR! Key spoofing')
        sys.exit()

    # step 3
    message = K_sym + bytes(userName_padding, 'ascii')
    c = bobRSA.encrypt(message)
    connection_to_Bob.send(c)
    message = connection_to_Bob.recv(1024)
    nonce = message[:16]
    tag = message[16:32]
    enc_R_b = message[32:]
    AEScipher = AES.new(K_sym, AES.MODE_GCM, nonce=nonce)
    plain_R_b = AEScipher.decrypt(enc_R_b)

    try:
        AEScipher.verify(tag)
    except ValueError:
        print("Key incorrect or message corrupted")

    R_b_1 = plain_R_b[:-1]
    AEScipher = AES.new(K_sym, AES.MODE_GCM)
    nonce_to_Bob = AEScipher.nonce
    ciphertext, tag_to_bob = AEScipher.encrypt_and_digest(R_b_1)
    message = nonce_to_Bob + tag_to_bob + ciphertext
    connection_to_Bob.send(message)

    return K_sym, connection_to_Bob


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
    message = myUserName + '/' + alice_name
    server_connect.send(message.encode())

    # step 5
    message = b''
    for _ in range(10):
        message_enc = client.recv(2048)
        message += SERVER_RSA.decrypt(message_enc)
        client.send('ACK'.encode())

    alice_name_check = message[:20].decode()
    alice_key = RSA.importKey(message[20:])
    if alice_name_check != alice_name:
        print('ERROR!!! INCORRECT MESSAGE FROM SERVER')

    aliceRSA = PKCS1_OAEP.new(alice_key)

    # step 6
    R_b = get_random_bytes(8)
    message = R_a + R_b
    message_enc = aliceRSA.encrypt(message)
    Client_to_Alice.send(message_enc)

    # step 7
    enc_message = Client_to_Alice.recv(2048)
    R_b_Alice = userRSA.decrypt(enc_message)
    if R_b_Alice != R_b:
        print('ERROR!!! Message spoofing in Alice side!')

    # step 3
    dec_part = b''
    message_enc = Client_to_Alice.recv(128)
    dec_part = userRSA.decrypt(message_enc)

    K_sym = dec_part[:16]
    alice_name_check2 = dec_part[16:]
    AEScipher = AES.new(K_sym, AES.MODE_GCM)
    nonce = AEScipher.nonce
    enc_R_b, tag = AEScipher.encrypt_and_digest(R_b)
    message = nonce + tag + enc_R_b
    Client_to_Alice.send(message)

    message_enc = Client_to_Alice.recv(1024)
    nonce_from_Alice = message_enc[:16]
    tag = message_enc[16:32]
    ciphertext = message_enc[32:]
    AEScipher_from_Alice = AES.new(K_sym, AES.MODE_GCM, nonce=nonce_from_Alice)
    plain_R_b_1 = AEScipher_from_Alice.decrypt(ciphertext)

    try:
        AEScipher_from_Alice.verify(tag)
    except ValueError:
        print("Key incorrect or message corrupted")

    if R_b[:-1] != plain_R_b_1:
        print('ERRRRRRROR')
        sys.exit()

    print('OK2')
    return K_sym, Client_to_Alice


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
        connect_to_bob.send(message_enc)
        # __________________________
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

        nonce_alice = cipher_to_alice[:16]
        tag_alice = cipher_to_alice[16:32]
        cipher_ma = cipher_to_alice[32:]
        AEScipher = AES.new(K_sym, AES.MODE_GCM, nonce=nonce_alice)
        message_from_alice = AEScipher.decrypt(cipher_ma).decode()
        try:
            AEScipher.verify(tag_alice)
        except ValueError:
            print("Key incorrect or message corrupted (alice side)")
        if message_from_alice.find('quit') != -1:
            break
        print(message_from_alice)
        # _________________________
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
        if operation.lower() == 'quit' or operation.lower() == 'q':
            break
        elif operation.lower() == 'list' or operation.lower() == 'l':
            client.send(operation.lower()[0].encode())
            print_user_list(client)
        ###
        elif operation.lower() == 'connect' or operation.lower() == 'c':
            client.send(operation.lower()[0].encode())
            K_sym, connect_to_bob = initiate_connection(client, client_name)
            messenger_for_alice(K_sym, connect_to_bob, client_name)
            operation = 'quit'
            break
        ###
        elif operation.lower() == 'wait connection' or operation.lower() == 'w':
            client.send(operation.lower()[0].encode())
            print(client.recv(1024).decode())
            K_sym, connect_to_alice = connect_to_user(client, userRSA, client_name)
            messenger_for_bob(K_sym, connect_to_alice, client_name)
            operation = 'quit'
            break

        ###
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')

    # if operation.lower() == 'quit' or operation.lower() == 'q':
    client.send(operation.lower()[0].encode())
    client.close()
