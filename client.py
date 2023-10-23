import hashlib
import socket
import socket
import sys
import ecdsa


def create_my_name(sc, pk_sign):
    flagName = False
    name = ''

    sc.send(str(pk_sign.to_der()).encode())
    while not flagName:
        name = input(sc.recv(1024).decode())
        sc.send(name.encode())
        flagName = (sc.recv(1024).decode() == 'True')
    return name


def print_operations():
    print("Options:")
    print("\t Enter 'quit' or 'q' to exit")
    print("\t Enter 'list' or 'l' to list established secure users")
    print("\t Enter 'connect' or 'c' to start conversation")


def print_user_list(client):
    UserName = client.recv(2048).decode()
    # print('Connected users:\n', ', '.join(UserName))
    print('Connected users:\n', UserName)


def initiate_connection(client):
    flagRecipient = False
    recipient_name = ''

    while not flagRecipient:
        recipient_name = input(client.recv(1024).decode())
        client.send(recipient_name.encode())
        flagRecipient = (client.recv(512) == 'True')

    return recipient_name


####################################
def get_dgst_keys():
    # sk
    s = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    # pk
    v = s.get_verifying_key()
    return s, v


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
    sk_sign, pk_sign = get_dgst_keys()
    client_name = create_my_name(client, pk_sign)
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
            rec_name = initiate_connection(client)
            get_keys(client)
        ###
        elif operation.lower() == 'quit' or operation.lower() == 'q':
            client.send(operation.lower()[0].encode())
            break
        ###
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')
    client.close()
