# symmetric
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES

# asymmetric
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

# hash
from Crypto.Hash import SHA256

# util
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import time




# #DES ecb
#
# def encrypt_des_ecb(plaintext):
#     # 64 bits key - 54 are used for encryption, 8 were used for integrity
#     key = get_random_bytes(8)
#     cipher = DES.new(key, DES.MODE_ECB)
#     ciphertext = cipher.encrypt(plaintext)
#     return ciphertext, key
#
#
# def decrypt_des_ecb(ciphertext, key):
#     cipher = DES.new(key, DES.MODE_ECB)
#     plaintext = cipher.decrypt(ciphertext)
#     return plaintext


# DES cbc

def encrypt_des_cbc(plaintext):
    # 64 bits key - 54 are used for encryption, 8 were used for integrity
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    return ciphertext, key, cipher.iv


def decrypt_des_cbc(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext


# DES3 cbc

def encrypt_des3_cbc(plaintext):
    while True:
        try:
            key = DES3.adjust_key_parity(get_random_bytes(24))
            break
        except ValueError:
            pass
    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    return ciphertext, key, cipher.iv


def decrypt_des3_cbc(ciphertext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext


# Blowfish cbc

def encrypt_blowfish_cbc(plaintext, key_length):
    if key_length % 8 != 0:
        raise ValueError('Blowfish key length should be divisible by 8')
    if key_length < 32 or key_length > 448:
        raise ValueError('Blowfish key length can vary from 32 to 448 bits')

    key = get_random_bytes(key_length//8)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, Blowfish.block_size))
    return ciphertext, key, cipher.iv


def decrypt_blowfish_cbc(ciphertext, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return plaintext


# AES cbc

def encrypt_aes_cbc(plaintext, key_length):
    if key_length != 128 and key_length != 192 and key_length != 256:
        raise ValueError('AES key length should be equal to 128 or 192 or 256')
    key = get_random_bytes(key_length//8)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, key, cipher.iv


def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


# RSA

def gen_key_rsa(key_length):
    if key_length != 1024 and key_length != 2048 and key_length != 3072 and key_length != 4096:
        raise ValueError('RSA key length should be equal to 1024 or 2048 or 3072 or 4096')
    key = RSA.generate(key_length)
    private_key = key
    public_key = key.public_key()

    return private_key, public_key


def encrypt_rsa(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def decrypt_rsa(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


# DSA

def gen_key_dsa(key_length):
    if key_length != 1024 and key_length != 2048 and key_length != 3072:
        raise ValueError('RSA key length should be equal to 1024 or 2048 or 3072')
    key = DSA.generate(key_length)
    private_key = key
    public_key = key.public_key()

    return private_key, public_key


def sign_dsa(msg, private_key):
    hash_obj = SHA256.new(msg)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)

    return signature


def verify_dsa(msg, signature, public_key):
    hash_obj = SHA256.new(msg)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except ValueError:
        return False