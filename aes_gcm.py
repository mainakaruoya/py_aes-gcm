"""
An implementation of AES in Galois/Counter Mode (GCM), that tries to follow the specification set out in NIST Special Publication 800-38D.
It relies on the Rijndael cipher, defined spearately in `rijndael.py` and which *must* be present
"""

from os import urandom
from math import ceil
import rijndael

class EncryptionFailure(ValueError):
    pass


# This constant defines the acceptable values for the tags produced by the authenticated enryption function. Anything not defined here will not work. In the standard, the values are in bits ([128, 120, 112, 104, 96]); here, the values are listed in bytes
SUPPORTED_TAG_LENGTHS = [16, 15, 14, 13, 12]

# This is the value - the error code - returned by our authenticated decryption function if the tag does not match the original tag produced by the authenticated encryption function
FAIL = "FAIL"

# These values determine the maximum allowable lengths for the plaintext, additional authenticated data (AAD), and the initialization vector as defined on p. 8 of the standard. Rather than calculate on the fly, it is better to hardcode them. These values have been converted to bytes
MAXIMUM_MESSAGE_LENGTH = 68719476704 # (2 ^ 39) - 256
MAXIMUM_AAD_LENGTH = 2305843009213693952 # (2 ^ 64) - 1
MAXIMUM_IV_LENGTH = 2305843009213693952 # (2 ^ 64) - 1


# For this case, we will have the GCM functionality and data encapsulated in a class.
# The relevant data are the key, the initialization vector, and the expected length of the authentication tag
class AES_GCM:

    """
    This class is meant to encapsulate all of the `AES-GCM` functionality as one unit.
    
    Attributes:
    keyToUse: The key that will be used by all relevant operations in this class
    initializationVector: The initialization vector that will be used by all relevant operations in this class
    authenticationTagLength: The length of the authentication tag used to guarantee authenticity of the data being signed.
    """

    def __init__(self, keyToUse: bytes, initializationVector: bytes, authenticationTagLength: int) -> None:
        
        self.keyToUse = keyToUse
        self.initializationVector = initializationVector
        self.authenticationTagLength = authenticationTagLength


    # Section 6: Mathematical Components of GCM
    # Section 6.2 - Incrementing Function
    @staticmethod
    def _incrementingFunction(bitStringToIncrement: bytes):
        """
        This function is used to generate the counter blocks needed for the cipher.
        
        Per the other GCM functions that use this function, the default number of bits to increment is 32.
        """
        # It is this value that we increment, and not the original slice we get from the bitStringToIncrement. Since bytes are immutable, trying to increment that slice will never work, since the string will only revert to the original.
        leastSignificantBitsInteger = int.from_bytes(bitStringToIncrement[-4:], byteorder="big")

        while True:

            leastSignificantBits = leastSignificantBitsInteger.to_bytes(4, byteorder="big")
            
            yield bitStringToIncrement[:12] + leastSignificantBits

            leastSignificantBitsInteger = (leastSignificantBitsInteger + 1) % pow(2, 32)

    # Section 6.3 - Multiplication Operation on Blocks
    @staticmethod
    def _blockMultiplication(firstBlock: bytes, secondBlock: bytes) -> bytes:

        # This value is defined in the standard; for simplicity, and since it doesn't change, it is hardcoded here
        constantR = b'\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        stringInBinary = lambda x: format(x, "b").zfill(128)
        bitStringX = stringInBinary(int.from_bytes(firstBlock))

        # We define our initial values of Z and V over here - the values Z0 and V0
        blockZ = bytes(16)
        blockV = secondBlock

        # The reason we start from index 1, and not 0, is because we already have the values V0 and Z0
        for value in range(0, 128):
            
            if bitStringX[value] == "0":
                temp = blockZ
                blockZ = temp

            if bitStringX[value] == "1":
                blockZ = bytes(a ^ b for a, b in zip(blockZ, blockV, strict=True))

            # Per the standard, the two if statements below check the last bit of the block V; since it would be more work to process the value to get the last bit, the easiest solution was to pick a proxy checking mechanism - if the value is even or odd. If a value is even, the last bit will always be 0, if odd, the last bit will always be 1.

            if blockV[-1] % 2 == 0:
                tempBlockV = int.from_bytes(blockV) >> 1
                blockV = int.to_bytes(tempBlockV, 16)

            if blockV[-1] % 2 == 1:
                temp = (int.from_bytes(blockV) >> 1).to_bytes(16)
                blockV = bytes(a ^ b for a, b in zip(temp, constantR, strict=True))

        return blockZ

    # Section 6.4 - GHASH Function
    # 6.4.1 - Generating the subkey
    # Since the GHASH function proper requires the hash subkey - where we apply the Rijndael cipher to the zero block, we first need to define that functionality
    @staticmethod
    def _generateHashSubkey(keyToUse: bytes) -> bytes:

        zeroBlock = bytes(16)

        hashSubKey = rijndael.encrypt(keyToUse, zeroBlock)

        return hashSubKey

    # 6.4.2 - GHASH function proper
    @staticmethod
    def _gHashFunction(blockToProcess: bytes, hashSubKey: bytes) -> bytes:

        # The standard uses 128 because it is working in bits; since the operations here are defined in bytes, that is why we are using 16 and not 128
        bitStringLength = len(blockToProcess) // 16

        # This value as defined here is our initial value of Y (Y0)
        blockY = bytes(16)

        # Rather than pre-divide the blockToProcess, these values will serve as the indices that mark the sliding window we will use when evaluating our blockToProcess
        firstIndex = 0
        lastIndex = 16
        
        for _ in range(1, (bitStringLength + 1)):
            
            subsectionOfBlockToProcess = blockToProcess[firstIndex:lastIndex]

            temp = bytes(a ^ b for a, b in zip(blockY, subsectionOfBlockToProcess))

            blockY = AES_GCM._blockMultiplication(temp, hashSubKey)

            firstIndex += 16

            lastIndex += 16

        return blockY

    # Section 6.5 - GCTR Function
    @staticmethod
    def _gCtrFunction(keyToUse: bytes, initialCounterBlock: bytes, bitString: bytes) -> bytes:

        ciphertext = b""

        if bitString == b"":
            return ciphertext
        
        bitStringLength = len(bitString)
        
        # The standard uses 128 because it is working in bits; since the operations here are defined in bytes, that is why we are using 16 and not 128
        numberOfBlocks = ceil(bitStringLength / 16)

        # Rather than pre-divide the blockToProcess, these values will serve as the indices that mark the sliding window we will use when evaluating our blockToProcess
        firstIndex = 0
        lastIndex = 0

        firstCounterBlock = initialCounterBlock
        
        counterBlockGenerator = AES_GCM._incrementingFunction(firstCounterBlock)

        nextCounterBlock = next(counterBlockGenerator)

        for blockIndex in range(numberOfBlocks):

            firstIndex = blockIndex * 16
            lastIndex = (blockIndex + 1) * 16

            if lastIndex > bitStringLength:
                break

            encipheredCounterBlock = rijndael.encrypt(keyToUse, nextCounterBlock)
            
            plaintextBlock = bitString[firstIndex:lastIndex]

            ciphertextBlock = bytes(a ^ b for a, b in zip(encipheredCounterBlock, plaintextBlock, strict=True))
            ciphertext += ciphertextBlock

            nextCounterBlock = next(counterBlockGenerator)
        
        # This section of code is meant to handle the last block which may be shorter than the cipher's block length - 16 bytes (128 bits)
        #---start---
        finalBlockLength = bitStringLength - firstIndex

        finalPlaintextBlock = bitString[firstIndex:bitStringLength]
        finalEncipheredCounterBlock = rijndael.encrypt(keyToUse, nextCounterBlock)[:finalBlockLength]

        finalCiphertextBlock = bytes(a ^ b for a, b in zip(finalEncipheredCounterBlock, finalPlaintextBlock, strict=True))

        ciphertext += finalCiphertextBlock
        #---end---

        return ciphertext


    # Section 7 - Galois/Counter Mode Specification
    # Section 7.1 - Authenticated Encryption
    @staticmethod
    def _gcmAuthenticatedEncryption(
            key: bytes, initializationVector: bytes,
            plaintext: bytes,
            additionalAuthenticatedData = b"",
            authenticationTagLength = 12
    ) -> tuple[bytes, bytes]:
        
        # Step 1: check if ciphertext, additional authenticated data, and initialization vector meet required lengths
        doesNotMeetLimits =  (len(plaintext) > MAXIMUM_MESSAGE_LENGTH) or (len(additionalAuthenticatedData) > MAXIMUM_AAD_LENGTH) or (len(initializationVector) > MAXIMUM_IV_LENGTH or len(initializationVector) < 1)

        # A generic error message to prevent attackers from deducing anything more about the cryptosystem based on the errors returned.
        if doesNotMeetLimits == True:
            raise EncryptionFailure("Encryption failure.")

        hashSubkey = AES_GCM._generateHashSubkey(key)

        initializationVectorLength = len(initializationVector)

        if initializationVectorLength == 12:

            preCounterBlockJ0 = initializationVector + b'\x00\x00\x00\x01'

        else:

            paddingLengthS = (16 * ceil(initializationVectorLength / 16)) - initializationVectorLength
            byteStringToHash = initializationVector + bytes((paddingLengthS + 8)) + int.to_bytes(initializationVectorLength, 8)
            preCounterBlockJ0 = AES_GCM._gHashFunction(byteStringToHash, hashSubkey)

        incrementedCounterBlock = next(AES_GCM._incrementingFunction(preCounterBlockJ0))

        ciphertext = AES_GCM._gCtrFunction(key, incrementedCounterBlock, plaintext)

        ciphertextLength = len(ciphertext)
        aadLength = len(additionalAuthenticatedData)

        # Generate block to use for creating authentication tag
        paddingU = (16 * ceil(ciphertextLength / 16)) - ciphertextLength
        paddingV = (16 * ceil(aadLength / 16)) - aadLength

        blockToHash = additionalAuthenticatedData + bytes(paddingV) + ciphertext + bytes(paddingU) + int.to_bytes(aadLength, 8, byteorder="big") + int.to_bytes(ciphertextLength, 8, byteorder="big")
        hashedBlockS = AES_GCM._gHashFunction(blockToHash, hashSubkey)

        # Then, generate the authentication tag
        authenticationTag = AES_GCM._gCtrFunction(key, preCounterBlockJ0, hashedBlockS)[:authenticationTagLength]

        return ciphertext, authenticationTag

    # Section 7.2 - Authenticated Decryption
    @staticmethod
    def _gcmAuthenticatedDecryption(
            key: bytes, initializationVector: bytes,
            ciphertext: bytes,
            authenticationTag: bytes,
            additionalAuthenticatedData = b"",
            authenticationTagLength = 12
    ) -> bytes | str:
        
        # Step 1: check if ciphertext, additional authenticated data, and initialization vector meet required lengths
        doesNotMeetLimits =  (len(ciphertext) > MAXIMUM_MESSAGE_LENGTH) or (len(additionalAuthenticatedData) > MAXIMUM_AAD_LENGTH) or (len(initializationVector) > MAXIMUM_IV_LENGTH or len(initializationVector) < 1)

        # A generic error message to prevent attackers from deducing anything more about the cryptosystem based on the errors returned.
        if doesNotMeetLimits == True:
            return FAIL

        hashSubkey = AES_GCM._generateHashSubkey(key)

        initializationVectorLength = len(initializationVector)

        if initializationVectorLength == 12:

            preCounterBlockJ0 = initializationVector + b'\x00\x00\x00\x01'

        else:

            paddingLengthS = (16 * ceil(initializationVectorLength / 16)) - initializationVectorLength
            byteStringToHash = initializationVector + bytes((paddingLengthS + 8)) + int.to_bytes(initializationVectorLength, 8)
            preCounterBlockJ0 = AES_GCM._gHashFunction(byteStringToHash, hashSubkey)

        incrementedCounterBlock = next(AES_GCM._incrementingFunction(preCounterBlockJ0))

        recoveredPlaintext = AES_GCM._gCtrFunction(key, incrementedCounterBlock, ciphertext)

        ciphertextLength = len(ciphertext)
        aadLength = len(additionalAuthenticatedData)

        # Generate block to use for creating authentication tag
        paddingU = (16 * ceil(ciphertextLength / 16)) - ciphertextLength
        paddingV = (16 * ceil(aadLength / 16)) - aadLength

        blockToHash = additionalAuthenticatedData + bytes(paddingV) + ciphertext + bytes(paddingU) + int.to_bytes(aadLength, 8, byteorder="big") + int.to_bytes(ciphertextLength, 8, byteorder="big")
        hashedBlockS = AES_GCM._gHashFunction(blockToHash, hashSubkey)

        # Then, generate the authentication tag
        tagToCompare = AES_GCM._gCtrFunction(key, preCounterBlockJ0, hashedBlockS)[:authenticationTagLength]

        if tagToCompare == authenticationTag:
            return recoveredPlaintext
        else:
            return FAIL


    # encrypt() and decrypt() - additional functions
    # The two function below are not defined by the standard. However, they serve as a useful interface to the end-user who only needs to access them and not the rest of the internal functionality. As such, the other functions are defined as class methods by use of the @staticmethod decorator
    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:

        ciphertext, authenticationTag = AES_GCM._gcmAuthenticatedEncryption(self.keyToUse, self.initializationVector, plaintext)

        # print(f"Our ciphertext is:\n{ciphertext.hex(":")}")
        # print(f"\nOur authentication tag is:\n{authenticationTag.hex(":")}")

        return ciphertext, authenticationTag

    def decrypt(self, ciphertext: bytes, authenticationTag: bytes) -> bytes | str:
        
        plaintext = AES_GCM._gcmAuthenticatedDecryption(self.keyToUse, self.initializationVector, ciphertext, authenticationTag)

        return plaintext


if __name__ == "__main__":

    print("Hello...\n")

    # Test code

    initializationVector = urandom(12)
    key = urandom(32)
    
    ourCryptosystem = AES_GCM(key, initializationVector, 16)

    plaintext = "Top threats on branch PINs include endpoint malware (point-of-sale [POS] malware), wireless infrastructure exploits such as rogue APs and man-in-the-middle (MitM) attacks, unauthorized/malicious client activity, and exploitation of trust.".encode("utf-8")

    ciphertext, tag = ourCryptosystem.encrypt(plaintext)
    print(f"Our ciphertext is:\n{ciphertext.hex(":")}")
    print(f"\nOur authentication tag is:\n{tag.hex(":")}")

    recoveredPlaintext = ourCryptosystem.decrypt(ciphertext, tag)
    
    if isinstance(recoveredPlaintext, bytes):
        print("\nDecryption successful.\n")
        print(f"Our recovered plaintext is:\n{recoveredPlaintext.decode()}") 
    else:
        print("Decryption failure.")




