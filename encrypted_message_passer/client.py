"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
	A Riker Morss
	Julian Lamberttes
	Jacob Johnson
"""

import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

iv = "G4XO4L\X<J;MPPLD"

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# TODO: Generate a random AES key
def generate_key():
    key = get_random_bytes(16)
    return key


# TODO: Takes an AES session key and encrypts it using the server's
# TODO: public key and returns the value
def encrypt_handshake(session_key):
    recipient_key = RSA.importKey(open('id_rsa.pub', 'rb').read())
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    # pad_key = pad_message(session_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key


# TODO: Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # Encrypt the data with the AES session key
    # cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, b'0123456789123456')  # Cipher block chaining with init val
    ciphertext = cipher_aes.encrypt(message.encode("utf-8"))
    return ciphertext


# TODO: Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # Decrypt the data with the AES session key
    # cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, b'0123456789123456')  # Cipher block chaining with init val
    decoded_message = cipher_aes.decrypt(message)
    return decoded_message


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # TODO: Generate random AES key
        # Generate new AES key
        key_AES = generate_key()

        # TODO: Encrypt the session key using server's public key
        # Make encrypted AES key for handshake
        key_encrypted = encrypt_handshake(key_AES)

        # TODO: Initiate handshake
        # Send encrypted AES key to socket for handshake
        send_message(sock, key_encrypted)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        # Encrypt message with AES key
        message_encrypted = encrypt_message(pad_message(message), key_AES)
        # Send message to socket
        send_message(sock, message_encrypted)

        # TODO: Receive and decrypt response from server and print
        # Receive message from socket
        message_received = receive_message(sock)
        # Decrypt received message with AES key
        message_decrypted = decrypt_message(message_received, key_AES)
        # Remember to decode message from 'utf-8'
        print(message_decrypted.decode('utf-8'))

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
