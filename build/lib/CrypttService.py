import base64
import os
import types
import typing
from typing import Dict, Union

from Crypto.Cipher import AES, Blowfish, DES3
from Crypto.Util import Padding


class CrypttService:
    block_size: int
    key_lengths: typing.List[int]
    encrypt_fn: typing.Callable[[str], bytes]
    decrypt_fn: typing.Callable[[str], bytes]
    block_cipher_mode: int
    algorithm_module: types.ModuleType
    key: bytes

    def __init__(self, block_cipher_mode: str, algorithm: str, key: str):
        mode_conf = self.get_block_cipher_modes_config()[block_cipher_mode]
        algorithm_conf = self.get_algorithms_config()[algorithm]
        self.block_cipher_mode = mode_conf['mode']
        self.encrypt_fn = mode_conf['encrypt_fn']
        self.decrypt_fn = mode_conf['decrypt_fn']
        self.algorithm_module = algorithm_conf['module']
        self.key_lengths = algorithm_conf['key_lengths']
        self.block_size = algorithm_conf['block_size']
        self.key = base64.b64decode(key.encode("ascii"))
        self.__check_key()

    def encrypt(self, plaintext: str) -> bytes:
        return self.encrypt_fn(self, plaintext)

    def decrypt(self, cipher_text: str) -> bytes:
        return self.decrypt_fn(self, cipher_text)

    @classmethod
    def get_block_cipher_modes_config(cls) -> Dict[str, Dict[str, Union[typing.Callable, int]]]:
        return {
            'ECB': {
                'encrypt_fn': cls.encrypt_ecb,
                'decrypt_fn': cls.decrypt_ecb,
                'mode': AES.MODE_ECB
            },
            'CBC': {
                'encrypt_fn': cls.encrypt_classic,
                'decrypt_fn': cls.decrypt_classic,
                'mode': AES.MODE_CBC
            },
            'CFB': {
                'encrypt_fn': cls.encrypt_classic,
                'decrypt_fn': cls.decrypt_classic,
                'mode': AES.MODE_CFB
            },
            'OFB': {
                'encrypt_fn': cls.encrypt_classic,
                'decrypt_fn': cls.decrypt_classic,
                'mode': AES.MODE_OFB
            },
            'AEAD': {
                'encrypt_fn': cls.encrypt_eax,
                'decrypt_fn': cls.decrypt_eax,
                'mode': AES.MODE_EAX
            }
        }

    @staticmethod
    def get_algorithms_config() -> Dict[str, Dict[str, Union[types.ModuleType, int, typing.List[int]]]]:
        return {
            'AES': {
                'module': AES,
                'block_size': 16,
                'key_lengths': [16, 24, 32]
            },
            'Blowfish': {
                'module': Blowfish,
                'block_size': 8,
                'key_lengths': range(5, 56, 1)
            },
            'DES3': {
                'module': DES3,
                'block_size': 8,
                'key_lengths': [16, 24]
            }
        }

    # encryption
    def encrypt_ecb(self, plaintext: str) -> bytes:
        cipher = self.algorithm_module.new(self.key, self.block_cipher_mode)
        padded = Padding.pad(plaintext.encode("ascii"), self.block_size)
        ciphertext = cipher.encrypt(padded)
        return base64.b64encode(ciphertext)

    def encrypt_classic(self, plaintext: str) -> bytes:
        iv = os.urandom(self.block_size)
        padded = Padding.pad(plaintext.encode("ascii"), self.block_size)
        cipher = self.algorithm_module.new(self.key, self.block_cipher_mode, iv)
        cipher_text = cipher.encrypt(padded)
        cipher_bytes = iv + cipher_text
        return base64.b64encode(cipher_bytes)

    def encrypt_eax(self, plaintext: str) -> bytes:
        cipher = self.algorithm_module.new(self.key, self.block_cipher_mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("ascii"))
        cipher_bytes = cipher.nonce + tag + ciphertext
        return base64.b64encode(cipher_bytes)

    # decryption
    def decrypt_eax(self, cipher_text: str) -> bytes:
        cipher_bytes = base64.decodebytes(cipher_text.encode("ascii"))
        nonce, tag, ciphertext = [cipher_bytes[x:y] for x, y in (
            (0, self.block_size), (self.block_size, 2 * self.block_size), (2 * self.block_size, len(cipher_bytes)))]
        cipher = self.algorithm_module.new(self.key, self.block_cipher_mode, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def decrypt_ecb(self, cipher_text: str) -> bytes:
        cipher_bytes = base64.decodebytes(cipher_text.encode("ascii"))
        cipher = self.algorithm_module.new(self.key, self.block_cipher_mode)
        encode = Padding.unpad(cipher.decrypt(cipher_bytes), self.block_size)
        return encode

    def decrypt_classic(self, cipher_text: str) -> bytes:
        cipher_bytes = base64.decodebytes(cipher_text.encode("ascii"))
        iv = cipher_bytes[:self.block_size]
        cipher = self.algorithm_module.new(self.key, self.block_cipher_mode, iv)
        plaintext = Padding.unpad(cipher.decrypt(cipher_bytes[self.block_size:]),
                                  self.block_size)
        return plaintext

    def __check_key(self):
        if len(self.key) not in self.key_lengths:
            raise Exception("ERROR: key length must be in " + self.key_lengths.__str__() + " but was " + str(
                len(self.key)) + " bytes")
