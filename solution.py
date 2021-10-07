#! /usr/bin/env python3

import cryptography
import nacl.secret
from nacl.secret import SecretBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import sys
import json
import secrets


with open(sys.argv[1]) as json_data:
    inputs = json.load(json_data)

outputs = {}



def AES_encrypt_block(key, block):
    assert len(key) == 16
    assert len(block) == 16
    # If you'd like to understand these two lines, come back after Problem 4.


#inputs = json.load(sys.stdin)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
    return cipher.encryptor().update(block)


# Problem 1
input_asciistr = inputs["problem1"].encode()
prblm1_key= ('A' * 16).encode()


prblm1_hex=AES_encrypt_block(prblm1_key,input_asciistr).hex()
outputs["problem1"] = prblm1_hex


# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
