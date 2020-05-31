from more_itertools import flatten

# Rijndael S box https://en.wikipedia.org/wiki/Rijndael_S-box

sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

sboxInv = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]


def sub_bytes(block):
    for i in range(len(block)):
        block[i] = sbox[block[i]]
    return block


def sub_bytes_inv(block):
    for i in range(len(block)):
        block[i] = sboxInv[block[i]]
    return block


def __xor__(x, y):
    if len(x) != len(y):
        raise Exception("Vector xor: Length of x and y should be the same.")
    return [(x[j] ^ y[j]) for j in range(len(x))]


def rotate(word, n):
    return word[n:] + word[0:n]


def row_shift(block):
    for i in range(4):
        block[i * 4:i * 4 + 4] = rotate(block[i * 4:i * 4 + 4], i)
    return block


def row_shift_inv(block):
    for i in range(4):
        block[i * 4:i * 4 + 4] = rotate(block[i * 4:i * 4 + 4], -i)
    return block


# Rijndael mixcolumns https://en.wikipedia.org/wiki/Rijndael_MixColumns

mcol = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
mcolInv = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def __gmul__(a, b):
    # Galois Field (256) Multiplication of two Bytes
    p = 0
    for counter in range(8):
        if (b & 1) != 0:
            p = p ^ a
        hi_bit_set = (a & 0x80) != 0
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p % 256


def mix_column(column):
    # 's' is the main State matrix, 'ss' is a temp matrix of the same dimensions as 's'.
    res = [0, 0, 0, 0]
    for i in range(4):
        for j in range(4):
            res[i] ^= __gmul__(mcol[i][j], column[j])
    return res


def mix_column_inv(column):
    res = [0, 0, 0, 0]
    for i in range(4):
        for j in range(4):
            res[i] ^= __gmul__(mcolInv[i][j], column[j])
    return res


# Rcon(0) is 0x8d because 0x8d multiplied by 0x02 is 0x01 in the finite field.
rc = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def expand_key(key):
    def rot_word(word):
        return [word[1], word[2], word[3], word[0]]

    if isinstance(key, str):
        key = bytes.fromhex(key)
    w = [[key[4 * i + j] for j in range(4)] for i in range(4)]
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = [(sbox[x] ^ rc[i // 4]) for x in rot_word(temp)]
        w.append(__xor__(w[i - 4], temp))
    return [list(flatten([w[4 * i + j] for j in range(4)])) for i in range(11)]


def matrix_to_columns(matrix):
    return [[matrix[i * 4 + j] for i in range(4)] for j in range(4)]


def columns_to_matrix(columns):
    return [columns[i][j] for j in range(4) for i in range(4)]


def to_byte_array(s):
    b = bytearray()
    b.extend(map(ord, s))
    return b


def AES_round(block):
    if len(block) != 16:
        raise Exception('block size must be 128 bits / 16 bytes')
    if any([block[x] >= 256 for x in range(len(block))]):
        raise Exception('Each element must be 1 byte / 8 bits long')
    block = [sbox[x] for x in block]
    block = row_shift(block)
    columns = matrix_to_columns(block)
    columns = [mix_column(c) for c in columns]
    block = columns_to_matrix(columns)
    return block


def AES_round_rev(block):
    columns = matrix_to_columns(block)
    columns = [mix_column_inv(c) for c in columns]
    block = columns_to_matrix(columns)
    block = row_shift_inv(block)
    block = [sboxInv[x] for x in block]
    return block


def AES_final_round(block):
    if len(block) != 16:
        raise Exception('block size must be 128 bits / 16 bytes')
    if any([block[x] >= 256 for x in range(len(block))]):
        raise Exception('Each element must be 1 byte / 8 bits long')
    block = [sbox[x] for x in block]
    block = row_shift(block)
    return block


def AES_final_round_rev(block):
    block = row_shift_inv(block)
    block = [sboxInv[x] for x in block]
    return block


def encrypt_block(block, key):
    if isinstance(block, str):
        block = to_byte_array(block)
    keys = expand_key(key)
    for i in range(9):
        block = [(block[j] ^ keys[i][j]) for j in range(len(block))]
        block = AES_round(block)
    block = __xor__(block, keys[9])
    block = AES_final_round(block)
    block = __xor__(block, keys[10])
    return bytes(block)


def decrypt_block(block, key):
    if isinstance(block, str):
        block = bytes.fromhex(block)
    keys = expand_key(key)
    block = __xor__(block, keys[10])
    block = AES_final_round_rev(block)
    block = __xor__(block, keys[9])
    i = 8
    while i >= 0:
        block = AES_round_rev(block)
        block = __xor__(block, keys[i])
        i -= 1
    return bytes(block)


def AES_encrypt(plain_text, key, to_str=False):
    b = to_byte_array(plain_text) if isinstance(plain_text, str) else plain_text
    while len(b) % 16 != 0:
        b.append(0)
    b = [[b[i * 16 + j] for j in range(16)] for i in range(len(b) // 16)]
    if to_str:
        return ''.join([encrypt_block(x, key).hex() for x in b])
    return [encrypt_block(x, key) for x in b]


def AES_decrypt(cipher_text, key, to_str=True):
    b = bytes.fromhex(cipher_text) if isinstance(cipher_text, str) else cipher_text
    if len(b) % 16 != 0:
        raise Exception('AES cipher block size must be dividable by 16')
    b = [[b[i * 16 + j] for j in range(16)] for i in range(len(b) // 16)]
    return ''.join([decrypt_block(x, key).decode("utf-8") for x in b]) if to_str else [decrypt_block(x, key) for x in b]


def pad_text(b):
    pad = len(b) % 16
    if pad == 0:
        pad = 16
        b.append(pad)
    while len(b) % 16 != 0:
        b.append(pad)
    return b


def unpad_text(b):
    offset = b[-1][-1]
    if offset == 16:
        return b[0:-1]
    b[-1] = b[-1][0:offset]
    return b


class AES_CBC:
    def encrypt(self, plain_text, iv, key):
        b = to_byte_array(plain_text)
        iv = bytes.fromhex(iv)
        b = pad_text(b)
        b = [[b[i * 16 + j] for j in range(16)] for i in range(len(b) // 16)]
        curr = encrypt_block(iv, key)
        res = [iv]
        for block in b:
            block = __xor__(block, curr)
            block = AES_encrypt(block, key, to_str=False)[0]
            curr = block
            res.append(block)
        res = [x.hex() for x in res]
        return ''.join(res)

    def decrypt(self, plain_text, key):
        b = bytes.fromhex(plain_text)
        if len(b) % 16 != 0:
            raise Exception('AES cipher block size must be dividable by 16')
        iv = b[:16]
        b = [[b[i * 16 + j] for j in range(16)] for i in range(len(b) // 16)]
        b[0] = encrypt_block(iv, key)
        p = []
        for i in range(len(b) - 1, 0, -1):
            d_block = decrypt_block(b[i], key)
            p.insert(0, __xor__(d_block, b[i - 1]))
        p = unpad_text(p)
        p = [bytes(block).decode('utf-8') for block in p]
        return ''.join(p)


class AES_CTR:
    counter_value = 0

    def get_counter(self):
        res = str(hex(self.counter_value))[2:]
        self.counter_value += 1
        while len(res) < 16:
            res = '0' + res
        return res

    def __process__(self, b, nonce, key):
        res = []
        b = [[b[i * 16 + j] for j in range(16)] for i in range(len(b) // 16)]
        for i in range(len(b)):
            iv = nonce + self.get_counter()
            iv = bytes.fromhex(iv)
            pad = AES_encrypt(iv, key)[0]
            block = b[i]
            block = __xor__(block, pad)
            res.append(bytes(block))
        return res

    def encrypt(self, plain_text, nonce, key):
        b = to_byte_array(plain_text)
        b = pad_text(b)
        res = self.__process__(b, nonce, key)
        res = [x.hex() for x in res]
        return ''.join(res)

    def decrypt(self, cipher_text, nonce, key):
        b = bytes.fromhex(cipher_text)
        p = self.__process__(b, nonce, key)
        p = unpad_text(p)
        p = [x.decode('utf-8') for x in p]
        return ''.join(p)
