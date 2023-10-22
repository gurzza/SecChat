import socket
import socket
import sys


def create_my_name(sc):
    flagName = False

    while not flagName:
        name = input(sc.recv(1024).decode())
        sc.send(name.encode())
        flagName = (sc.recv(1024).decode() == 'True')


# def initiate_connection(client):
#
#     while
#     recipient_name = input(client.recv(1024).decode())
#     client.send(recipient_name.encode())


def print_operations():
    print("Options:")
    print("\t Enter 'quit' or 'q' to exit")
    print("\t Enter 'list' or 'l' to list established secure users")
    print("\t Enter 'connect' or 'c' to start conversation")


def print_user_list(client):
    pass


if __name__ == '__main__':
    # create connection
    SERVER_NAME = 'DESKTOP-7FRD9J8'
    SERVER_IP = socket.gethostbyname(SERVER_NAME)
    PORT = 8081

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #try:
    client.connect((SERVER_IP, PORT))
    #except:
    #   sys.exit()
    #########

    # log in
    create_my_name(client)
    #########


    operation = ''
    while 1:
        print_operations()
        operation = input()
        if operation.lower() == 'list' or operation.lower() == 'l':
            client.send(operation.encode())
            print_user_list(client)
        elif operation.lower() == 'connect' or operation.lower() == 'c':
            client.send(operation.encode())
            initiate_connection(client)
        elif operation.lower() == 'quit' or operation.lower() == 'q':
            client.send(operation.encode())
            break
        else:
            print('ERROR! NO SUCH OPERATION! TRY ONE MORE TIME...\n')
    client.close()
