# simes: Simple Encrypted Socket Library

## Overview
**simes** is a Python library designed to facilitate secure and easy-to-use encrypted communication over sockets. It provides a suite of tools for encrypting and decrypting messages sent over TCP/IP, ensuring that your data remains private and secure during transmission.

## Features
- **AES Encryption**: Utilizes Advanced Encryption Standard (AES) in CBC mode for strong encryption.
- **Automatic Padding**: Handles padding of messages to fit block size requirements.
- **IV Management**: Securely generates and manages Initialization Vectors (IVs) for each encryption operation.
- **Key Management**: Offers a simple interface for managing encryption keys.
- **Error Handling**: Robust error handling for common issues like message size limits and unknown senders.
- **Socket Communication**: Seamlessly integrates with Python's `socket` module for network communications.

## Installation
To install `simes`, you can simply use pip:
```bash
pip install simes
```

## Usage
Here's a quick example to get you started with `simes`:

### Encrypting and Sending a Message
```python
import socket
from simes import sendEncryptedJSON

# Setup socket and key
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
key = b'secret_key_16_byte'

# Encrypt and send a message
data = {"message": "Hello, World!"}
sendEncryptedJSON(sock, 'sender_name', data, key)
```

### Receiving and Decrypting a Message
```python
from simes import receiveEncryptedJSON

# Assuming 'sock' is a socket object

keys_dict	= {'sender_name': b'secret_key_16_byte'}

data = receiveEncryptedJSON(sock, keys_dict)
print(data)
```

Check the test directory for more examples.

## Contributing
Contributions to `simes` are welcome!

## License
`simes` is released under the [MIT License](LICENSE).

