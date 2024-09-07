### Advanced Encryption Standard in Galois/Counter Mode (AES-GCM)
This is a CLI-based implementation of AES-GCM in Python. It takes a plaintext message, the key size (128, 192, or 256 bits) to use, and the length of the authentication tag to be used (a value between 12-16 bytes), and then encrypts and decrypts the message, printing out the ciphertext, and the subsequent decrypted ciphertext (i.e., the original plaintext).

This implementation has endeavored to follow what is defined in the US NIST Special Publication SP 800-38D, found [here](https://doi.org/10.6028/NIST.SP.800-38D) (link is to a PDF document; alternatively, the publication's web page is [here](https://csrc.nist.gov/pubs/sp/800/38/d/final)).

**Note:** The program only accepts characters that can be represented as values between 0-255.

### ⚠️ Disclaimer
Though this implementation over here aimed to follow the standard as closely as possible, it is not recommended to use this in a production environment. It is better to use libraries like `Cryptogrpahy`, `PyNaCl` and `Pycryptodome` which have been more thoroughly vetted and importantly, generally optimized for such use.

### Prerequisites
The plaintext, key length, and decoded plaintext are color-coded using `colorama`, hence the need to install it using pip:
`pip install colorama`


### Usage
### `rijndael.py`
This is the core algorithm for AES - more particularly, the forward cipher of the Rijndael algorithm. It follows what is defined in the US NIST FIPS 197 publication, found [here](https://doi.org/10.6028/NIST.FIPS.197-upd1).

### `aes_gcm.py`
This script implements the AES-GCM mode, drawing on `rijndael.py` for use in its internal functionality. It is what contains our authenticated encryption and authenticated decryption functionality. Since it is defined as a kind of module, you can import its functionality into your program.

### `aes_cli.py`
This is the CLI implementation of the AES-GCM cryptosystem, which calls `aes_gcm.py` to perform authenticated encryption and authenticated decryption on whatever plaintext the user supplies.

The command to use (all arguments are mandatory):

`aes_cli.py [-h] -l <key length> -t <tag length> -m <plaintext>`

~~~
options:
  -h, --help            show this help message and exit
  -l <key length>, --length <key length>
                        Key length for the AES function. The possible values that can be selected are 128, 192, or 256 bits.
  -t <tag length>, --taglength <tag length>
                        The length of the authentication tag. The possible values are 12, 13, 14, 15, or 16 bytes, per the standard.
  -m <plaintext>, --message <plaintext>
                        The message to encrypt and decrypt.
~~~