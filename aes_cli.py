"""
This script allows us to use the AES-GCM functionality via a command line terminal.
"""
from aes_gcm import AES_GCM
from os import urandom
import argparse
# colorama is for coloring some of the output shown on the screen
from colorama import init as colorama_init, Fore, Style

colorama_init()

parser = argparse.ArgumentParser(
    description="This is a CLI-based interface for AES in Galois/Counter Mode (AES-GCM). The user supplies the key length (128, 192, or 256 bits), and the size of the authentication tag (12, 13, 14, 15, or 16 bytes), and a plaintext message, which is then encrypted (with the ciphertext printed to screen). Decryption is also performed, with the following caveat: if the authentication tag is valid, we get our plaintext; if not, we get a decryption failure message."
)

parser.add_argument("-l", "--length", metavar="<key length>", type=int, choices=[
                    128, 192, 256], help="Key length for the AES function. The possible values that can be selected are 128, 192, or 256 bits.", required=True)

parser.add_argument("-t", "--taglength", metavar="<tag length>", type=int, choices=[
                    12, 13, 14, 15, 16], help="The length of the authentication tag. The possible values are 12, 13, 14, 15, or 16 bytes, per the standard.", required=True)

parser.add_argument("-m", "--message", metavar="<plaintext>", type=str,
                    help="The message to encrypt and decrypt.", required=True)


def parseInput() -> None:

    receivedArguments = parser.parse_args()
    keyLength = receivedArguments.length
    authenticationTagLength: int = receivedArguments.taglength
    message: str = receivedArguments.message.encode("utf-8")

    print(f"Our message is:\n{Style.BRIGHT}{Fore.BLUE}{message}{Style.RESET_ALL}")
    print(f"\nSelected key length is:\n{Style.BRIGHT}{Fore.YELLOW}{keyLength} bits{Style.RESET_ALL}")
    print(f"\nSelected authentication tag length is:\n{Style.BRIGHT}{Fore.LIGHTRED_EX}{authenticationTagLength} bytes{Style.RESET_ALL}")

    keyLengthInBytes = keyLength // 8
    keyToUse = urandom(keyLengthInBytes)

    # The length of the initialization vector is fixed at 12 bytes
    initializationVector = urandom(12)

    cryptosystem = AES_GCM(keyToUse, initializationVector, authenticationTagLength)

    ciphertext, tag = cryptosystem.encrypt(message)
    print(f"\nOur ciphertext is:\n{Style.BRIGHT}{Fore.GREEN}{ciphertext.hex(":")}{Style.RESET_ALL}")
    print(f"\nOur authentication tag is:\n{Style.BRIGHT}{Fore.GREEN}{tag.hex(":")}{Style.RESET_ALL}")

    recoveredPlaintext = cryptosystem.decrypt(ciphertext, tag)

    if isinstance(recoveredPlaintext, bytes):
        print("\nDecryption successful.\n")
        print(f"Our recovered plaintext is:\n{Style.BRIGHT}{Fore.YELLOW}{recoveredPlaintext.decode()}{Style.RESET_ALL}")
    else:
        print("Decryption failure.")


if __name__ == '__main__':
    parseInput()
