"""
A variation of an earlier version of the Rijndael algorithm implemented by yours truly. It aims to follow closely the FIPS 197 standard.
Specifically, just the forward cipher since that is all that is used by the CTR mode, which is in turn used by AES in GCM Mode.
"""
from os import urandom
from secrets import randbits

# S-Box constants in hexadecimal format, as found in the AES FIPS Standard
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# The round constants for generating the key schedule in hex format
# ROUND_CONSTANTS_KEYEXPANSION = [
#     0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
# ]
ROUND_CONSTANTS_KEYEXPANSION = [
    [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
]


# Generate the key to be used by the algorithm - use the keyLength as determinant for key length
# For cryptographically secure random bits, we use the urandom() function from the os module
# The other number returned is the number of rounds that we expect our Rijndael function to be run
def generateKey(selectedKeySize: int) -> tuple[int, bytes]:
    if selectedKeySize == 128:
        return 10, urandom(int(selectedKeySize / 8))
    if selectedKeySize == 192:
        return 12, urandom(int(selectedKeySize / 8))
    if selectedKeySize == 256:
        return 14, urandom(int(selectedKeySize / 8))


# Our function for substituting a character per the SBox defined above
def sBoxFunction(singleByte: bytes) -> bytes:
    return S_BOX[singleByte]


# Step 4: Key expansion: Three parts
# Function 4.1: SubWord() function - used by the key expansion function
def subWord(word: bytes) -> bytes:

    substitutedBytes = b''

    for byte in word:
        substitutedBytes += S_BOX[byte].to_bytes()

    return substitutedBytes

# Function 4.2: RotWord() function - used by the key expansion function
def rotWord(word: bytes) -> bytes:

    rotatedValues = [
        value.to_bytes() for value in [word[1], word[2], word[3], word[0]]
        ]
    
    return b''.join(rotatedValues)

# Function 4.3: Key expansion proper - in the AES FIPS document, the expanded key is called the key schedule
def generateKeySchedule(rounds: int, initialKey: bytes) -> tuple[int, bytes]:

    # The byte string that will hold the expanded key which we return
    expandedKey = b''

    # Counter for round expansion
    count = 0
    keyLengthinWords = int(len(initialKey) / 4)

    # This produces the expanded values in groups of 4 values, taken from the key itself
    while count <= keyLengthinWords - 1:

        valueToAppend = b"".join(
            value.to_bytes() for value in [initialKey[0 + (4 * count)], initialKey[1 + (4 * count)], initialKey[2 + (4 * count)], initialKey[3 + (4 * count)]]
        )
        expandedKey += valueToAppend

        count += 1

    # This section produces the rest of the key schedule, using some round constants as well as other words currently in the key schedule
    while (count <= ((4 * rounds) + 3)):

        temporaryValue = expandedKey[count:(count + 4)]

        # We subtract 1 from the ROUND_CONSTANTS_KEYEXPANSION index because our round constants are indexed from 0, whilst in the standard the indices start at 1
        if (count % keyLengthinWords) == 0:

            temporaryValue = b''.join( [
                (a ^ b).to_bytes() for a, b in zip(subWord(rotWord(temporaryValue)), ROUND_CONSTANTS_KEYEXPANSION[int(count / keyLengthinWords) - 1])
                ]
            )

            expandedKey += temporaryValue

        elif keyLengthinWords > 6 and (count % keyLengthinWords == 4):

            expandedKey += subWord(temporaryValue)

        else:

            indexToUse = count - keyLengthinWords
            temporaryValue = b''.join( [
                (a ^ b).to_bytes() for (a, b) in zip(expandedKey[indexToUse:(indexToUse + 4)], temporaryValue)]
                )
            expandedKey += temporaryValue

        count += 1

    return rounds, expandedKey


# Step 5: The forward cipher - the one that 'encrypts' our plaintext
# Depends on other functions created here, as well as the sBoxFunction() defined earlier
# Function 5.1: AddRoundKey()
def addRoundKey(plaintextBlock: bytes, roundKey: bytes) -> bytes:
    
    roundKeyAdded = bytes(a ^ b for a, b in zip(plaintextBlock, roundKey, strict=True))

    return roundKeyAdded

# Function 5.2: SubBytes()
# This susbtitutes the bytes in the bytestring supplied to it, based on values in the S_BOX defined above
def subBytes(valuesToSubstitute: bytes) -> bytes:

    substitutedValues = [S_BOX[item].to_bytes() for item in valuesToSubstitute]

    return b''.join(substitutedValues)

# Function 5.3: ShiftRows()
# Probably the simplest way - hardcoding indices for each value, and returning the list directly as opposed to assigning it to a variable.
def shiftRows(valuesToShift: bytes) -> bytes:
    
    shiftedValues = [value.to_bytes() for value in [
        valuesToShift[0], valuesToShift[5], valuesToShift[10], valuesToShift[15],
        valuesToShift[4], valuesToShift[9], valuesToShift[14], valuesToShift[3],
        valuesToShift[8], valuesToShift[13], valuesToShift[2], valuesToShift[7],
        valuesToShift[12], valuesToShift[1], valuesToShift[6], valuesToShift[11]
        ]
    ]

    return b''.join(shiftedValues)

# Function 5.4: MixColumns()
# Function 5.4.1: xTimes(), which is referenced by the MixColumns() function. It uses multiplication in a Galois (finite) field, which is slightly different from normal multiplication.
def xTimes(listEntry: bytes, multiplier: int) -> bytes:

    if multiplier == 2 and listEntry & 0x80:

        byte = listEntry << 1
        byte ^= 0x1b
        byte &= 0xff
        return byte
    
    elif multiplier == 2:

        byte = listEntry << 1
        byte &= 0xff
        return byte
    
    elif multiplier == 3:
        return listEntry ^ xTimes(listEntry, 2)

# Function 5.4.2: MixColumns() proper
def mixColumns(columns: bytes) -> bytes:

    mixedValues = b""

    numberOfColumns = int(len(columns) / 4)

    for columnIndex in range(numberOfColumns):

        newValues = b"".join([
            value.to_bytes() for value in [
                xTimes(columns[(columnIndex * 4) + 0], 2) ^ xTimes(columns[(columnIndex * 4) + 1], 3) ^ columns[(columnIndex * 4) + 2] ^ columns[(columnIndex * 4) + 3],
                columns[(columnIndex * 4) + 0] ^ xTimes(columns[(columnIndex * 4) + 1], 2) ^ xTimes(columns[(columnIndex * 4) + 2], 3) ^ columns[(columnIndex * 4) + 3],
                columns[(columnIndex * 4) + 0] ^ columns[(columnIndex * 4) + 1] ^ xTimes(columns[(columnIndex * 4) + 2], 2) ^ xTimes(columns[(columnIndex * 4) + 3], 3),
                xTimes(columns[(columnIndex * 4) + 0], 3) ^ columns[(columnIndex * 4) + 1] ^ columns[(columnIndex * 4) + 2] ^ xTimes(columns[(columnIndex * 4) + 3], 2)
            ]
        ])

        mixedValues += newValues

    return mixedValues

# Function 5.5: The forward cipher proper
def rijndaelForwardCipher(messageBlock: bytes, numberOfRounds: int, keySchedule: bytes) -> bytes:
    
    encryptedBlock = b''

    initializedState = addRoundKey(messageBlock, keySchedule[0:16])

    for iteration in range(1, numberOfRounds):

        firstIndex = (iteration * 16)
        lastIndex = ((iteration + 1) * 16)

        subBytesState = subBytes(initializedState)
        shiftRowsState = shiftRows(subBytesState)
        mixColumnsState = mixColumns(shiftRowsState)

        initializedState = addRoundKey(mixColumnsState, keySchedule[firstIndex : lastIndex])

    finalSubBytesState = subBytes(initializedState)
    finalShiftRowsState = shiftRows(finalSubBytesState)
    finalAddRoundKeyState = addRoundKey(finalShiftRowsState, keySchedule[(numberOfRounds * 16):])

    encryptedBlock += finalAddRoundKeyState

    return encryptedBlock

def encrypt(keyToUse: bytes, message: bytes) -> bytes:
    if len(keyToUse) == 16:
        rounds = 10
    if len(keyToUse) == 24:
        rounds = 12
    if len(keyToUse) == 32:
        rounds = 14
    
    numberOfRounds, keySchedule = generateKeySchedule(rounds, keyToUse)

    encryptedBlock = rijndaelForwardCipher(message, numberOfRounds, keySchedule)

    return encryptedBlock

if __name__ == '__main__':
    rounds, key = generateKey(128)
    numberOfRounds, expandedKey = generateKeySchedule(rounds, key)

    blockToUse = randbits(128).to_bytes(length=16)

    encryptedBlock = rijndaelForwardCipher(blockToUse, numberOfRounds, expandedKey)
    print(f"Our encrypted block is: {encryptedBlock.hex(":")}")
