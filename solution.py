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
    return data+pad.hex()

def unpad(plain_text):
    last_character = plain_text[len(plain_text) - 1:]
    bytes_to_remove = ord(last_character)
    return plain_text[:-bytes_to_remove]

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
    padded_data=pad_(x,16)
    final_array5.append(padded_data)

outputs["problem5"] = final_array5


# Problem 6
prblm6_hex = inputs["problem6"]
final_array6 =[]
for x in prblm6_hex:
    unpadded_data=unpad(bytes.fromhex(x))
    final_array6.append(unpadded_data.decode())

outputs["problem6"] = final_array6


# Problem 7
prblm7_hex = inputs["problem7"]
lyric_sbytes=prblm7_hex["lyrics"].encode().hex()
key=prblm7_hex["key"]

problem7=""
repeats =[]
final_array7 =[]
padded_data=bytes.fromhex(pad_(lyric_sbytes,16))
for x in range(0, len(padded_data), 16):
    encrypted_val7=AES_encrypt_block(bytes.fromhex(key),padded_data[x:x+16]).hex()
    if encrypted_val7 in problem7:
        repeats.append(encrypted_val7)

    problem7=problem7+encrypted_val7

outputs["problem7"] = {
    "ciphertext": problem7,
    "repeats" : repeats
}



# Output
#
# In the video I wrote something more like `json.dump(outputs, sys.stdout)`.
# Either way works. This way adds some indentation and a trailing newline,
# which makes things look nicer in the terminal.
print(json.dumps(outputs, indent="  "))
