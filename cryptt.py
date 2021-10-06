import os
from io import BufferedReader

import click
from Crypto.Cipher import AES
from Crypto.Util import Padding


def decrypt_eax(input_file, output_file, key_file, block_cypher_mode):
    nonce, tag, ciphertext = [input_file.read(x) for x in (16, 16, -1)]
    cipher = AES.new(__check_and_read_key(key_file), block_cypher_mode, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    output_file.write(data)


def decrypt_ecb(input_file, output_file, key_file, block_cypher_mode):
    ciphertext = input_file.read()
    cipher = AES.new(__check_and_read_key(key_file), block_cypher_mode)
    plaintext = Padding.unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    output_file.write(plaintext)


def decrypt_classic(input_file, output_file, key_file, block_cypher_mode):
    ciphertext = input_file.read()
    iv = ciphertext[:BLOCK_SIZE]
    cipher = AES.new(__check_and_read_key(key_file), block_cypher_mode, iv)
    plaintext = Padding.unpad(cipher.decrypt(ciphertext[BLOCK_SIZE:]), BLOCK_SIZE)
    output_file.write(plaintext)


def encrypt_ecb(input_file, output_file, key_file, block_cypher_mode):
    cipher = AES.new(__check_and_read_key(key_file), block_cypher_mode)
    plaintext = Padding.pad(input_file.read(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext)
    output_file.write(ciphertext)


def encrypt_classic(input_file, output_file, key_file, block_cypher_mode):
    iv = os.urandom(BLOCK_SIZE)
    plaintext = Padding.pad(input_file.read(), BLOCK_SIZE)
    cipher = AES.new(__check_and_read_key(key_file), block_cypher_mode, iv)
    ciphertext = cipher.encrypt(plaintext)
    [output_file.write(x) for x in (iv, ciphertext)]


def encrypt_eax(input_file, output_file, key_file, block_cypher_mode):
    cipher = AES.new(__check_and_read_key(key_file), block_cypher_mode)
    ciphertext, tag = cipher.encrypt_and_digest(input_file.read())
    [output_file.write(x) for x in (cipher.nonce, tag, ciphertext)]


block_cypher_modes = {
    'ECB': {
        'encrypt_fn': encrypt_ecb,
        'decrypt_fn': decrypt_ecb,
        'mode': AES.MODE_ECB
    },
    'CBC': {
        'encrypt_fn': encrypt_classic,
        'decrypt_fn': decrypt_classic,
        'mode': AES.MODE_CBC
    },
    'CTR': {
        'encrypt_fn': encrypt_classic,
        'decrypt_fn': decrypt_classic,
        'mode': AES.MODE_CTR
    },
    'CFB': {
        'encrypt_fn': encrypt_classic,
        'decrypt_fn': decrypt_classic,
        'mode': AES.MODE_CFB
    },
    'OFB': {
        'encrypt_fn': encrypt_classic,
        'decrypt_fn': decrypt_classic,
        'mode': AES.MODE_OFB
    },
    'AEAD': {
        'encrypt_fn': encrypt_eax,
        'decrypt_fn': decrypt_eax,
        'mode': AES.MODE_EAX
    }
}

BLOCK_SIZE = 16


@click.group()
def cli():
    pass


@cli.command()
@click.argument('input_file', type=click.File('rb'))
@click.argument('output_file', type=click.File('xb'))
@click.argument('key_file', type=click.File('rb'))
@click.option('--block_cypher_mode',
              type=click.Choice(list(block_cypher_modes.keys()), case_sensitive=False), prompt=True)
def encrypt(input_file, output_file, key_file, block_cypher_mode):
    mode_conf = block_cypher_modes[block_cypher_mode]
    mode_conf['encrypt_fn'](input_file, output_file, key_file, mode_conf['mode'])


@cli.command()
@click.argument('input_file', type=click.File('rb'))
@click.argument('output_file', type=click.File('xb'))
@click.argument('key_file', type=click.File('rb'))
@click.option('--block_cypher_mode',
              type=click.Choice(list(block_cypher_modes.keys()), case_sensitive=False), prompt=True)
def decrypt(input_file, output_file, key_file, block_cypher_mode):
    mode_conf = block_cypher_modes[block_cypher_mode]
    mode_conf['decrypt'](input_file, output_file, key_file, mode_conf['mode'])


def __check_and_read_key(key_file: BufferedReader):
    key_chunk = key_file.read(64)
    key_size = len(key_chunk)
    if key_size not in [16, 24, 32]:
        click.echo("ERROR: key length must be 16, 24 or 32 bytes, but was " + str(key_size) + " bytes")
        exit(1)
    return key_chunk
