"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
  	A Riker Morss
	Julian Lambert
	Jacob Johnson
"""

import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import hashlib

iv = "G4XO4L\X<J;MPPLD"

host = "localhost"
port = 10001


# This is handy to have as a global for debugging, but not secure..?
#private_key = RSA.import_key(open("private").read())


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# TODO: Write a function that decrypts a message using the server's private key
# im not sure if session key means private key, thats what im guessing
def decrypt_key(session_key):
    #global private_key  # See global variables at top of file
    private_key = RSA.importKey(open('id_rsa', 'rb').read())
    # file_in = open("encrypted_data.bin", "rb")
    # enc_session_key, nonce, tag, ciphertext = \
    #    [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_session_key = cipher_rsa.decrypt(session_key)

    # enc_session_key, nonce, tag, ciphertext = \
    #    [file_in.read(x) for x in (session_key.size_in_bytes(), 16, 16, -1)]
    # private_key = "MIIEpAIBAAKCAQEAzmx46T6fXszMpOSe4N3j3o9mqxhPJGiLb7YexKJNaO5q3+wyRawpZfJCHVJB2zgW2R9kAsY/zdneztFFAA7wB1NLPBqS4u10867TwuQOC5VCLAo/2nELQv9bFxYsdcL1hXMLyZ7rsndoO+a9RfyVBlqiYLDOXMpFzk0lq+FwANYwsnTEz8RDrdrfBWIwz/WCRIoU+5swNOAswnKi6aYWulF7rlla+aTtDRo0z5t4cyMmtikApQcj8T7LZEA8w3j/oCEMRCRyQ5AGaEwLr1CaNlik8MHQYw401M0S4eEmPtrmzRA0yGlBk4OexWgpG7g7wiH4Bc3YaCBTupn94UJpMQIDAQABAoIBAQDEfU5uv3RWed3Gi/SMGcrhPGE/NcmH35fyw0nwZIoI+wFymtOTrHhPmVXDsVwMvwxIqu+5EFsFqIDFH0Bt+MoUPv4bfTQanGu51c2u8wRHlFFDuJHlbbuJj6Z2iF3TzruExukOh57V54Gpm07Jgs+cF8P/A+27N7NQ1/Cm9tV1hLd6pbmi3sTxs3sDJ8W+xY+zesYc97lHquGJbBdBVnuC8tDfJiwT8VTmE/wBd2vvrfg0SNX2UEecmBtkIXyNc3gDQx1M3vB01Jo5WtE6iehi41XxERRjMlyYKZg0ITrerInLEjiKXrnyx7oLxDaweuyiZxJTR6pFYIeoc4MndvzBAoGBAOcnXSW2qa9YGIGnw1Zr87D2q23PZq5Yl2JpeLwyViP24z1+d9Vf6rVXBzauTjkr77RJCIZQ0Nqt2zExDL4pLpxyRpi4Q3SqEFlOw6SiDmv9/3l/bKqji7Kyd3Bk6wnLVbR0Iej9yrTIhmwRdgclPSnBC0sv0OllXcU3XK5fEZNpAoGBAOScnTlQ66JSkJivmLfvFGKDRvdX4I2ZecmcnEkGth9U69Y7knjCdXkwGgz5sPX9dD6dwmqVH4PheOaIGDK50rwFVUKLXWvPHPQjhWE9UPEZx/hFsaenMk6MdpHCME8/PNrkLUsUQTTQ7J++cjLRYYU0oL+ttd4vfa4rJSIgQ5aJAoGAHi15b68FQCsUJ/kq+2Fkkzng75kgIqrWOLbkWE2KCW/2AtU799Np5PrTqkPfWn9t7++I+WAbpDEGaMmqjDj8KNiSduW3iMebEs3BpQCzOU4TyFzmZvCrEE1UYowKU2EEc2al9rELgcacJgexjQVDkuvs+Yfokk/1igXMR8eJl+ECgYEAyaBbhnaZLBPX1eJhNjBVcUFJMNM/iIOJB0jqCfoyXFXgnpTx7THMu/Kxtyntajd889Dd7HTTU9Rjdicn+G0tsIifls4lufT0G1rMw2N55PsRBCYrtqre0qpN1OZJB0vF12SRkfsuO2/cklM8kxdaBErTT9rcYTbPiPIikQOVuMkCgYBwjHNu2LdC55+WVPcWla05iUWFAOWbMeckXkx5H2GVMEcYhHCYxRbn537GvAAxO7BqPGGcXwIb2goThDWAGhGtyKjV4e8jkY7+lV+C4mriYiWglHKZZoSNfm9B+IvFZ1XD4PV9TcQMaxD7X54d2ei1R7tB0rA3Afqp0l5HfvWrDA=="

    return decrypted_session_key


# TODO: Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # Decrypt the data with the AES session key
    # cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, b'0123456789123456')  # Cipher block chaining w init value
    decrypted_message = cipher_aes.decrypt(client_message)
    return decrypted_message


# TODO: Encrypt a message using the session key
def encrypt_message(message, session_key):
    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_CBC, b'0123456789123456')  # Cipher block chaining w init value
    ciphertext = cipher_aes.encrypt(message.encode("utf-8"))  # Don't forget to encode to utf-8!!
    return ciphertext


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                passed = hashlib.sha512((password + line[1]).encode()).hexdigest()
                if (passed == line[2]):
                    return True
                else:
                    return False
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # Decrypt message from client
                plaintext_message = decrypt_message(ciphertext_message, plaintext_key)

                # Split response from user into the username and password

                user, password = plaintext_message.split()

                user = user.decode('utf-8')
                password = password.decode('utf-8')

                if verify_hash(user, password):
                    plaintext_response = "User successfully authenticated!"
                else:
                    plaintext_response = "Password or username incorrect"

                # Encrypt response to client
                ciphertext_response = encrypt_message(pad_message(plaintext_response), plaintext_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
