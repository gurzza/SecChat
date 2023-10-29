import hashlib
import socket
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

SERVER_RSA_N = 0
SERVER_RSA_E = 0
# CLIENT_RSA_KEYS = []
PORT_FOR_BOB = 10_000


def create_my_name(sc):
    flagName = False
    name = ''
    global SERVER_RSA_E
    global SERVER_RSA_N
    userKeys = RSA.generate(1024)

    # n exchange
    sc.send(int(userKeys.n).to_bytes(128, "big"))
    SERVER_RSA_N = int.from_bytes(sc.recv(256), "big")
    # e exchange
    sc.send(int(userKeys.e).to_bytes(18, "big"))
    SERVER_RSA_E = int.from_bytes(sc.recv(18), "big")

    print('n\n', SERVER_RSA_N)
    print('e\n', SERVER_RSA_E)
    print('c_n\n', userKeys.n)
    print('c_e\n', userKeys.e)

    while not flagName:
        name = input(sc.recv(1024).decode())
        sc.send(name.encode())
        flagName = (sc.recv(1024).decode() == 'True')
    return name, userKeys


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
    client.send((UserName + '/' + recipient_name).encode())

    # step 2: {K_b, B}  \\K_t(-1) <--
    message = client.recv(8192).decode()
    print('SERVER_RSA_N:', SERVER_RSA_N)
    if ord(recipient_name[0]) % 2 != ord(message[0]) % 2:
        print('ERROR!!! Message substitution has been occurred...')
        sys.exit()
    n_end = message.find('/')
    bob_n = pow(int(message[1: n_end]), SERVER_RSA_E, SERVER_RSA_N)
    bob_e = pow(int(message[n_end + 1:]), SERVER_RSA_E, SERVER_RSA_N)

    # step 3
    bob_host = client.recv(1024).decode()
    print('bob_host', bob_host)
    # create connection
    connection_to_Bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_to_Bob.connect((bob_host, PORT_FOR_BOB))
    # T + {Ra, A}
    connection_to_Bob.send(UserName.encode())  # send my name
    connection_to_Bob.recv(1024)  # ACK
    message = str(int(client.getpeername()[0][0]) % 2)
    R_a = int.from_bytes(get_random_bytes(8), "big")
    print('ALICE R_a:', R_a)
    message_to_enc = str(ord(UserName[0]) % 2) + str(R_a)
    enc_message = pow(int(message_to_enc), bob_e, bob_n)
    message_to_send = message + str(enc_message)
    connection_to_Bob.send(message_to_send.encode())

    # step 6
    enc_message = connection_to_Bob.recv(2048).decode()
    message = pow(int(enc_message), CLIENT_RSA_KEYS.d, CLIENT_RSA_KEYS.n)
    R_a_Bob = str(message)[:len(str(R_a))]
    if int(R_a_Bob) != R_a:
        print('ERROR!!! Message spoofing!')
        sys.exit()
    R_b = int(str(message)[len(str(R_a)):])
    print('ALICE R_b:', R_b)

    # step 7
    enc_message = pow(R_b, bob_e, bob_n)
    connection_to_Bob.send(str(enc_message).encode())

    return recipient_name

####################################


def connect_to_user(server_connect, MY_RSA_KEYS, myUserName):
    clientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    HOSTNAME = socket.gethostname()
    HOST_IP = socket.gethostbyname(HOSTNAME)
    PORT = 10_000
    try:
        clientSocket.bind((HOST_IP, PORT))
    except socket.error as e:
        print(str(e))
    clientSocket.listen(1)
    Client_to_Alice, address = clientSocket.accept()
    ####
    # step 3
    alice_name = Client_to_Alice.recv(1024).decode()
    Client_to_Alice.send('ACK'.encode())
    message = Client_to_Alice.recv(1024).decode()
    first_letter_Alice = str(message)[0]
    dec_message = pow(int(str(message)[1:]), MY_RSA_KEYS.d, MY_RSA_KEYS.n)
    R_a = str(dec_message)[1:]
    #print('Bob R_a:', R_a)

    # step 4
    # alice_ip, alice_port = Client_to_Alice.getpeername()
    # print('port_type:', type(alice_port))
    message = myUserName + '/' + alice_name
    print('sended mes:', message)
    server_connect.send(message.encode())

    # step 5
    ser_message = server_connect.recv(2048).decode()
    if ser_message[0] != first_letter_Alice:
        print('ERROR!!! INCORRECT MESSAGE FROM SERVER')
    enc_alice_n, enc_alice_e = ser_message[1:].split('/')
    alice_e = pow(int(enc_alice_e), SERVER_RSA_E, SERVER_RSA_N)
    alice_n = pow(int(enc_alice_n), SERVER_RSA_E, SERVER_RSA_N)

    # print('alice_e: ', alice_e)
    # print('alice_n: ', alice_n)

    # step 6
    R_b = int.from_bytes(get_random_bytes(8), "big")
    print('Bob R_b', R_b)
    message = str(R_a) + str(R_b)
    enc_message = pow(int(message), alice_e, alice_n)
    Client_to_Alice.send(str(enc_message).encode())

    # step 7
    enc_message = Client_to_Alice.recv(2048).decode()
    R_b_Alice = pow(int(enc_message), MY_RSA_KEYS.d, MY_RSA_KEYS.n)
    if R_b_Alice != R_b:
        print('ERROR!!! Message spoofing in Alice side!')



###############################

if __name__ == '__main__':
    # create connection
    SERVER_NAME = 'DESKTOP-7FRD9J8'
    SERVER_IP = socket.gethostbyname(SERVER_NAME)
    PORT = 8082

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # remove or keep try-except?
    # try:
    client.connect((SERVER_IP, PORT))
    # except:
    #   sys.exit()
    #########

    # log in

    client_name, CLIENT_RSA_KEYS = create_my_name(client)
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
            connect_to_user(client, CLIENT_RSA_KEYS, client_name)

        ###
        elif operation.lower() == 'quit' or operation.lower() == 'q':
            client.send(operation.lower()[0].encode())
            break
        ###
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')
    client.close()
