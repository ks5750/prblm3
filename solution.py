#! /usr/bin/env python3

import cryptography
import nacl.secret
from nacl.secret import SecretBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import sys
import json
import secrets


# with open(sys.argv[1]) as json_data:
#   inputs = json.load(json_data)
inputs = json.load(sys.stdin)

outputs = {}



def AES_encrypt_block(key, block):
    assert len(key) == 16
    assert len(block) == 16
    # If you'd like to understand these two lines, come back after Problem 4.
    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
    return cipher.encryptor().update(block)

def AES_decrypt_block(key, block):
    assert len(key) == 16
    assert len(block) == 16
    # If you'd like to understand these two lines, come back after Problem 4.
    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
    return cipher.decryptor().update(block)

# Problem 1
input_asciistr = inputs["problem1"].encode()
prblm1_key= ('A' * 16).encode()
prblm1_hex=AES_encrypt_block(prblm1_key,input_asciistr).hex()
outputs["problem1"] = prblm1_hex


# Problem 2
prblm2_hex = inputs["problem2"]
prblm1_key= ('A' * 16).encode()
prblm2_val=AES_decrypt_block(prblm1_key,bytes.fromhex(prblm2_hex)).decode()
outputs["problem2"] = prblm2_val


# Problem 3
prblm3_ascii = inputs["problem3"].encode()
problem3=""
for x in range(0, len(prblm3_ascii), 16):
    problem3=problem3+AES_encrypt_block(prblm1_key,prblm3_ascii[x:x+16]).hex()
outputs["problem3"] = problem3



# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
