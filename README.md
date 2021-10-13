CRYPTT
------

- Encrypt and decrypt files
- Use different block cipher modes
- Use different algorithms

### Get Started

Activate the virtual environment:

```source venv/bin/activate```

The script is added as an entry point, so it can be called directly via 'cryptt':

```cryptt --help```

```cryptt encrypt --help```

```cryptt decrypt --help```

There is a 24 byte and a 32 byte key for testing. Example for encrypting a file 'input.txt' into a file 'output.txt' with block cipher mode 'CBC' and algorithm 'Blowfish':

```cryptt encrypt input.txt output.txt 32byte.key --block-cipher-mode cbc --algorithm blowfish```