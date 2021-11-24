#!/usr/bin/env python3
#
# Author : fei.hao@mobvoi.com(Fei Hao)
# Date   : Wed Nov 24 10:25:41 CST 2021
#
"""A simple demo for symmetric encryption.
"""

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def get_bytes_from_file(filename):
    with open(filename, "rb") as fr:
        all_datas = fr.read()
    return all_datas


def write_bytes_to_file(filename, content):
    with open(filename, "wb") as fw:
        fw.write(content)


def symmetric_encode(key, iv, plaintext):
    """Symmetric encryption.
    """
    padder = padding.PKCS7(128).padder()
    plaintext = padder.update(plaintext)
    plaintext += padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def symmetric_decode(key, iv, ciphertext):
    """Symmetric decryption.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext += unpadder.finalize()
    return plaintext


if __name__ == "__main__":
    key = b"onegdo80123456wi5zep45v28rkg72vr"
    iv = b"rmbsczv0uohxl67e"

    if (sys.argv[1] == "-e"):
        plaintext = get_bytes_from_file(sys.argv[2])
        ciphertext = symmetric_encode(key, iv, plaintext)
        write_bytes_to_file("ciphertext", ciphertext)
    elif (sys.argv[1] == "-d"):
        ciphertext = get_bytes_from_file(sys.argv[2])
        plaintext = symmetric_decode(key, iv, ciphertext)
        write_bytes_to_file("plaintext", plaintext)
    else:
        print("Error")
