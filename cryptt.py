import os
from io import BufferedReader

import click
from CrypttService import CrypttService


@click.group()
def cli():
    """Encryption and decryption of files, using a range of algorithms and block cipher modes"""
    pass


@cli.command()
@click.argument('input_file', type=click.File('rb'))
@click.argument('output', type=click.File('xb'))
@click.argument('key_file', type=click.File('rb'))
@click.option('--block_cipher_mode',
              type=click.Choice(list(CrypttService.get_block_cipher_modes_config().keys()), case_sensitive=False),
              prompt=True)
@click.option('--algorithm',
              type=click.Choice(list(CrypttService.get_algorithms_config().keys()), case_sensitive=False),
              default='AES')
def encrypt(input_file: BufferedReader, output: BufferedReader, key_file: BufferedReader, block_cipher_mode: str,
            algorithm: str):
    """INPUT_FILE: path of file to be encrypted (must exist, or use "-" for stdin)\n
        OUTPUT: path of where the encrypted file will be stored (must not exist, use "-" for stdout)\n
        KEY_FILE: path of file with a base64 encrypted key (required key size differs depending on algorithm)"""
    try:
        key = key_file.read().decode()
        service = CrypttService(block_cipher_mode, algorithm, key)
        plaintext = input_file.read().decode()
        cipher_text = service.encrypt(plaintext)
        output.write(cipher_text)
    except Exception:
        os.remove(output.name)
        raise


@cli.command()
@click.argument('input_file', type=click.File('rb'))
@click.argument('output', type=click.File('xb'))
@click.argument('key_file', type=click.File('rb'))
@click.option('--block_cipher_mode',
              type=click.Choice(list(CrypttService.get_block_cipher_modes_config().keys()), case_sensitive=False),
              prompt=True)
@click.option('--algorithm',
              type=click.Choice(list(CrypttService.get_algorithms_config().keys()), case_sensitive=False),
              default='AES')
def decrypt(input_file: BufferedReader, output: BufferedReader, key_file: BufferedReader, block_cipher_mode: str,
            algorithm: str):
    """INPUT_FILE: path of file to be decrypted (must exist, or use "-" for stdin)\n
        OUTPUT: path of where the decrypted file will be stored (must not exist, use "-" for stdout)\n
        KEY_FILE: path of file with a base64 encrypted key (required key size differs depending on algorithm)"""
    try:
        key = key_file.read().decode()
        service = CrypttService(block_cipher_mode, algorithm, key)
        cipher_text = input_file.read().decode()
        plaintext = service.decrypt(cipher_text)
        output.write(plaintext)
    except Exception:
        os.remove(output.name)
        raise
