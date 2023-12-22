import os
import json

# Cryptography

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Exceptions

class UnknownSenderError(Exception):
    """Exception raised when an unknown sender is encountered."""
    pass

class NameTooLongError(Exception):
    """Exception raised when a name exceeds the allowed length."""
    pass

class MessageTooLongError(Exception):
    """Exception raised when a message exceeds the maximum allowed size."""
    pass

class InvalidStatusError(Exception):
    """Exception raised when an invalid status is provided."""
    pass

class PaddingValidationError(Exception):
    """Exception raised when padding validation fails."""
    pass

# block size is 128 bits since we're using AES, 128 bits = 16 bytes
SIMES_PADDING_SIZE     = 128  # bits

SIMES_IV_SIZE          = 16   # bytes

SIMES_SENDER_SIZE      = 16 # bytes, with 16 bytes we can write 16 characters with utf8

SIMES_MESSAGE_MAX_SIZE_VARIABLE = 16 # bytes, the max number which can be represented with 16 bytes is 2^(16*8) = 2^128
SIMES_MESSAGE_MAX_SIZE          = 2 ** (SIMES_MESSAGE_MAX_SIZE_VARIABLE * 8)

SIMES_STATUS_MAX_SIZE  = 16 # bytes, with 16 bytes we can write 16 characters with utf8

# Note that SIMES_SENDER_SIZE + SIMES_STATUS_MAX_SIZE % 16 == 0. This is compulsory
# This has to be done since status send/receive is not padded

if (SIMES_SENDER_SIZE + SIMES_STATUS_MAX_SIZE) % 16 != 0:
    raise PaddingValidationError("SIMES_SENDER_SIZE + SIMES_STATUS_MAX_SIZE % 16 != 0")

SIMES_AVAILABLE_STATUS = ["OK", "ERROR",
                          "HANDSHAKE",
                          "ACCEPTED", "NOT_ACCEPTED",
                          "START", "STOP", "PAUSE", "RESUME"]

# Check if all the available status are valid
for status in SIMES_AVAILABLE_STATUS:
    if len(status.encode('utf8')) > SIMES_STATUS_MAX_SIZE:
        raise NameTooLongError("Status name is too long")

def recv_all(sock, expected_size):
    """
    Receives the expected amount of data from the socket.

    Args:
    sock (socket.socket): The socket object.
    expected_size (int): The expected size of the data to receive.

    Returns:
    bytes: The received data.
    """
    data = b''
    while len(data) < expected_size:
        remaining_size = expected_size - len(data)
        packet = sock.recv(remaining_size)
        if not packet:
            raise ConnectionError("Socket connection broken")
        data += packet
    return data

def encryptRaw(data, key, pad_data = True):
    """
    Encrypts data with the given key. data is expected to be a bytes object.
    """

    # Generate a random IV
    iv = os.urandom(SIMES_IV_SIZE)

    # Setup the cipher
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    if pad_data:
        # Setup the padding
        padder = padding.PKCS7(SIMES_PADDING_SIZE).padder()

        # Encrypt the data
        padded_data    = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    else:
        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Return the encrypted data
    return iv + encrypted_data

def decryptRaw(data, key, pad_data = True):
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

    if pad_data:
        # Setup the unpadder
        unpadder = padding.PKCS7(SIMES_PADDING_SIZE).unpadder()

        # Decrypt the data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        data        = unpadder.update(padded_data) + unpadder.finalize()
    else:
        # Decrypt the data
        data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Return the decrypted data
    return data



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
    sender_bytes = sender.encode("utf8")

    if len(sender_bytes)   > SIMES_SENDER_SIZE:
        raise NameTooLongError("Sender name too long")
    if len(encrypted_data) > SIMES_MESSAGE_MAX_SIZE:
        raise MessageTooLongError("Message too long")

    # Add padding to the sender name. We add x20 (space) to the beginning of the sender name
    sender_bytes = b"\x20" * (SIMES_SENDER_SIZE - len(sender_bytes)) + sender_bytes

    # Create size bytes and add padding (we add x00 to the beginning of the size bytes)
    size_bytes = len(encrypted_data).to_bytes(SIMES_MESSAGE_MAX_SIZE_VARIABLE, byteorder="big")
    size_bytes = b"\x00" * (SIMES_MESSAGE_MAX_SIZE_VARIABLE - len(size_bytes)) + size_bytes

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
    data = json.dumps(data).encode("utf8")

    # Send the data
    sendEncryptedRaw(sock, sender, data, key)

def receiveEncryptedRaw(sock, keys_dict,timeout = None):
    """
    Receives encrypted data from the socket. Returns a bytes object.
    It is expected that the data was sent with sendEncryptedRaw.
    """

    sock.settimeout(timeout)

    sender_bytes = recv_all(sock,SIMES_SENDER_SIZE)
    size_bytes   = recv_all(sock,SIMES_MESSAGE_MAX_SIZE_VARIABLE)

    sender = sender_bytes.decode("utf8").strip()
    size   = int.from_bytes(size_bytes, byteorder="big")

    # Check if the sender is in the keys_dict
    if sender not in keys_dict:
        raise UnknownSenderError("Unknown sender")

    key = keys_dict[sender]

    encrypted_data = recv_all(sock,size)

    # Decrypt the data
    data = decryptRaw(encrypted_data, key)

    # Set timeout to None (blocking)
    sock.settimeout(None)

    # Return sender/data
    return sender, data

def receiveEncryptedJSON(sock, keys_dict):
    """
    Receives encrypted data from the socket. Returns a dict.
    It is expected that the data was sent with sendEncryptedJSON.
    """

    # Receive the data
    sender,data = receiveEncryptedRaw(sock, keys_dict)

    # Decode the data
    try:
        data = json.loads(data.decode("utf8"))
    except json.JSONDecodeError as e:
        raise e

    # Return sender/data
    return sender, data

# Status sending/receiving functions
def sendStatus(sock, sender, status, key):
    """
    Sends a status to the socket. status is expected to be a string.
    """

    # Check if the status is valid
    if status not in SIMES_AVAILABLE_STATUS:
        raise InvalidStatusError("Invalid status")

    # Create the message
    sender_bytes = sender.encode("utf8")

    if len(sender_bytes)   > SIMES_SENDER_SIZE:
        raise NameTooLongError("Sender name too long")

    # Add padding to the sender name. We add x20 (space) to the beginning of the sender name
    sender_bytes = b"\x20" * (SIMES_SENDER_SIZE - len(sender_bytes)) + sender_bytes

    status_bytes = status.encode("utf8")
    # Add padding to the status name. We add x20 (space) to the beginning of the status name
    status_bytes = b"\x20" * (SIMES_STATUS_MAX_SIZE - len(status_bytes)) + status_bytes
    # Encrypt the status
    encrypted_status = encryptRaw(status_bytes, key, pad_data = False)

    # Create the message
    message = sender_bytes + encrypted_status

    # Send the message
    sock.sendall(message)

def receiveStatus(sock, keys_dict, timeout = None):
    """
    Receives a status from the socket. Returns a string.
    """

    sock.settimeout(timeout)

    sender_bytes = recv_all(sock,SIMES_SENDER_SIZE)

    sender = sender_bytes.decode("utf8").strip()

    # Check if the sender is in the keys_dict
    if sender not in keys_dict:
        raise UnknownSenderError("Unknown sender")

    key = keys_dict[sender]

    # Receive the message
    encrypted_status = recv_all(sock,SIMES_IV_SIZE + SIMES_STATUS_MAX_SIZE)

    # Decrypt the status
    status = decryptRaw(encrypted_status, key, pad_data=False)

    # Set timeout to None (blocking)
    sock.settimeout(None)

    # Return sender/status
    return sender, status.decode("utf8").strip()
