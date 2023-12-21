import os
import json

import socket

# Cryptography

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# block size is 128 bits since we're using AES, 128 bits = 16 bytes
SIMES_PADDING_SIZE        = 128  # bits

SIMES_IV_SIZE             = 16   # bytes
SIMES_RECIEVE_BUFFER_SIZE = 1024 # bytes

SIMES_SENDER_SIZE      = 16 # bytes, with 16 bytes we can write 16 characters with utf8
SIMES_MESSAGE_MAX_SIZE = 16 # bytes, the max number which can be represented with 16 bytes is 2^(16*8) = 2^128
SIMES_STATUS_MAX_SIZE  = 16 # bytes, with 16 bytes we can write 16 characters with utf8

SIMES_AVAILABLE_STATUS = ["OK", "ERROR"]
# Check if all the available status are valid
for status in SIMES_AVAILABLE_STATUS:
    if len(status.encode(utf8)) > SIMES_STATUS_MAX_SIZE:
        raise Exception("Status name too long")

def encryptRaw(data, key):
    """
    Encrypts data with the given key. data is expected to be a bytes object.
    """

    # Generate a random IV
    iv = os.urandom(SIMES_IV_SIZE)

    # Setup the cipher
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Setup the padding
    padder = padding.PKCS7(SIMES_PADDING_SIZE).padder()

    # Encrypt the data
    padded_data    = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return the encrypted data
    return iv + encrypted_data


def sendEncryptedRaw(sock, sender, data, key):
    """
    Sends encrypted data to the socket. data is expected to be a bytes object.

    Two additional non encrypted fields are added to the message:
    - sender: the name of the sender of the message
    - size: the size of the encrypted data
    """

    # Encrypt the data
    encrypted_data = encryptRaw(data, key)

    # Create the message
    sender_bytes = sender.encode(utf8)

    if len(sender_bytes)   > SIMES_SENDER_SIZE:
        raise Exception("Sender name too long")
    if len(encrypted_data) > SIMES_MESSAGE_MAX_SIZE:
        raise Exception("Message too long")

    # Add padding to the sender name. We add x20 (space) to the beginning of the sender name
    sender_bytes = b"\x20" * (SIMES_SENDER_SIZE - len(sender_bytes)) + sender_bytes

    # Create size bytes and add padding (we add x00 to the beginning of the size bytes)
    size_bytes = len(encrypted_data).to_bytes(SIMES_MESSAGE_MAX_SIZE, byteorder="big")
    size_bytes = b"\x00" * (SIMES_MESSAGE_MAX_SIZE - len(size_bytes)) + size_bytes

    # Create the message
    message = sender_bytes + size_bytes + encrypted_data

    # Send the message
    sock.sendall(message)

def sendEncryptedJSON(sock, sender, data, key):
    """
    Sends encrypted data to the socket. data is expected to be a dict.

    Two additional non encrypted fields are added to the message:
    - sender: the name of the sender of the message
    - size: the size of the encrypted data
    """

    # Encode the data
    data = json.dumps(data).encode(utf8)

    # Send the data
    sendEncryptedRaw(sock, sender, data, key)

def decryptRaw(data, key):
    """
    Receives encrypted data. Returns a bytes object.
    It is expected that the data created with encryptRaw.
    """

    # Receive the message
    iv             = data[:SIMES_IV_SIZE]
    encrypted_data = data[SIMES_IV_SIZE:]

    # Setup the cipher
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_data    = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder       = padding.PKCS7(SIMES_PADDING_SIZE).unpadder()
    unpadded_data  = unpadder.update(padded_data) + unpadder.finalize()

    # Return the decrypted data
    return unpadded_data

def receiveEncryptedRaw(sock, keys_dict):
    """
    Receives encrypted data from the socket. Returns a bytes object.
    It is expected that the data was sent with sendEncryptedRaw.
    """

    sender_bytes = sock.recv(SIMES_SENDER_SIZE)
    size_bytes   = sock.recv(SIMES_MESSAGE_MAX_SIZE)

    sender = sender_bytes.decode(utf8).strip()
    size   = int.from_bytes(size_bytes, byteorder="big")

    # Check if the sender is in the keys_dict
    if sender not in keys_dict:
        raise Exception("Unknown sender")

    key = keys_dict[sender]

    # Receive the message
    encrypted_data = sock.recv(size)

    # Decrypt the data
    data = decryptRaw(encrypted_data, key)

    # Return the decrypted data
    return data

def receiveEncryptedJSON(sock, keys_dict):
    """
    Receives encrypted data from the socket. Returns a dict.
    It is expected that the data was sent with sendEncryptedJSON.
    """

    # Receive the data
    data = receiveEncryptedRaw(sock, keys_dict)

    # Decode the data
    try:
        data = json.loads(data.decode(utf8))
    except:
        raise Exception("Invalid data")

    # Return the data
    return data

# Status sending/receiving functions
def sendStatus(sock, sender, status, key):
    """
    Sends a status to the socket. status is expected to be a string.
    """

    # Check if the status is valid
    if status not in SIMES_AVAILABLE_STATUS:
        raise Exception("Invalid status")

    # Create the message
    sender_bytes = sender.encode(utf8)

    if len(sender_bytes)   > SIMES_SENDER_SIZE:
        raise Exception("Sender name too long")

    # Add padding to the sender name. We add x20 (space) to the beginning of the sender name
    sender_bytes = b"\x20" * (SIMES_SENDER_SIZE - len(sender_bytes)) + sender_bytes

    status_bytes = status.encode(utf8)
    # Add padding to the status name. We add x20 (space) to the beginning of the status name
    status_bytes = b"\x20" * (SIMES_STATUS_MAX_SIZE - len(status_bytes)) + status_bytes
    # Encrypt the status
    encrypted_status = encryptRaw(status_bytes, key)

    # Create the message
    message = sender_bytes + encrypted_status

    # Send the message
    sock.sendall(message)

def receiveStatus(sock, keys_dict):
    """
    Receives a status from the socket. Returns a string.
    """

    sender_bytes = sock.recv(SIMES_SENDER_SIZE)

    sender = sender_bytes.decode(utf8).strip()

    # Check if the sender is in the keys_dict
    if sender not in keys_dict:
        raise Exception("Unknown sender")

    key = keys_dict[sender]

    # Receive the message
    encrypted_status = sock.recv(SIMES_STATUS_MAX_SIZE)

    # Decrypt the status
    status = decryptRaw(encrypted_status, key)

    # Return the status
    return status.decode(utf8).strip()
