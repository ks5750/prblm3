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

def pad_(data,block_size):
    pad_size=(block_size - len(bytes.fromhex(data))) % block_size

    if pad_size == 0:
        pad_size=block_size

    pad =(chr(pad_size) * pad_size).encode()
    print(pad)
    return data+pad.hex()

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

# Problem 4
prblm4_hex = inputs["problem4"]
prblm4_ascii=bytes.fromhex(prblm4_hex)
problem4=""
for x in range(0, len(prblm4_ascii), 16):
    problem4=problem4+AES_decrypt_block(prblm1_key,prblm4_ascii[x:x+16]).decode()
outputs["problem4"] = problem4

# Problem 5
prblm5_hex = inputs["problem5"]
final_array5 =[]
for x in prblm5_hex:
    print(x,len(x))
    print(bytes.fromhex(x),len(bytes.fromhex(x)))
    padded_data=pad_(x,16)
    print(padded_data)
    final_array5.append(padded_data)

outputs["problem5"] = final_array5

# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
