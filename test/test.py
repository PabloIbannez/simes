import os

import threading
import socket

import traceback

import simes

# Simes functions:
#
# encryptRaw(data, key)
# decryptRaw(data, key)
#
# sendEncryptedRaw(sock, sender, data, key)
# sendEncryptedJSON(sock, sender, data, key)
#
# receiveEncryptedRaw(sock, keys_dict)
# receiveEncryptedJSON(sock, keys_dict)
#
# sendStatus(sock, sender, status, key)
# receiveStatus(sock, keys_dict)

# We test sendEncryptedJSON/receiveEncryptedJSON and sendStatus/receiveStatus
# functions since the rest of the functions are used by them.

##############################################################################################
#                Client                                                     Server
# 1.   HANDSHAKE                    ---------------------------->
# 2.                                <----------------------------   OK
# 3.   {"field1": "value1",
#       "field2": "value2",
#       "message": "Hello server!"} ---------------------------->
# 4.                                <---------------------------- {"message": "Hello client!"}
# 5.   STOP                         ---------------------------->
#
#
# Close socket
# Stop server thread

key = os.urandom(32)

key_dict = {
    "server": key,
    "client": key
}

host = '127.0.0.1'

server_port = 12345

def server(key_dict):

    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, server_port))

    # Listen for incoming connections
    sock.listen(1)

    # Wait for a connection
    print("Server: Waiting for a connection...")

    key = key_dict["client"]

    while True:
        connection, client_address = sock.accept()
        print("Server: Connection from", client_address)

        try:
            status = simes.receiveStatus(connection, key_dict)
            print("Server: Received status:", status)
            print("Server: Sending status OK")
            simes.sendStatus(connection, "server", "OK", key)

            data = simes.receiveEncryptedJSON(connection, key_dict)
            print("Server: Received data:", data)
            message = {"message": "Hello client!"}
            print("Server: Sending message:", message)
            simes.sendEncryptedJSON(connection, "server", message, key)

            status = simes.receiveStatus(connection, key_dict)
            if status == "STOP":
                print("Server: Received STOP signal")
                break
            else:
                print("Error: Server: Received wrong status:", status, "instead of STOP")
        finally:
            # Clean up the connection
            connection.close()

    sock.close()
    return

# Set up a thread for the server
server_thread = threading.Thread(target=server, args=(key_dict,))
server_thread.start()

# Create a socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, server_port))

    print("Client: Sending status HANDSHAKE...")
    simes.sendStatus(sock, "client", "HANDSHAKE", key)

    status = simes.receiveStatus(sock, key_dict)
    print("Client: Received status:", status)
    if status == "OK":
        message = {"field1": "value1", "field2": "value2", "message": "Hello server!"}
        print("Client: Sending message:", message)
        simes.sendEncryptedJSON(sock, "client", message, key)
        data = simes.receiveEncryptedJSON(sock, key_dict)
        print("Client: Received data:", data)
    else:
        print("Error: Client: Received wrong status:", status)

    print("Sending status STOP...")
    simes.sendStatus(sock, "client", "STOP", key)
    print("Closing client socket...")
    sock.close()
    # Stop the server thread
    server_thread.join()

except:
    traceback.print_exc()
    print("Something went wrong!")

    sock.close()
    # Stop the server thread
    server_thread.join()

print("Done.")

