# Advanced Encryption Standard Implementation

# How to run my program:
#
# Ensure the files you are trying to run against my program are
# located in the same directory as my py files.
#
# run this command on your command line:
#
# python aes_implementation.py <encrypt|decrypt> <key_file> <p-text OR c-text_file>
#
# By default you will see the CBC and EBC outputs, all you need to do is specify 'encryption' or 'decryption'


import os, sys
from sbox import sbox_map, inverse_sbox_map


# - Key Expansion ------------

# hard coding values into their proper positions
def rotate_left(word):
    rotated = [0] * 4
    rotated[0] = word[1]
    rotated[1] = word[2]
    rotated[2] = word[3]
    rotated[3] = word[0]
    return rotated

# uses an sbox hashmap to substitute values
# looks messy because this sbox has key:value pairs in the form of bridged strings-
# -so we need to do some conversions
def sub_bytes_word(word, sbox):
    result = []
    for byte in word:
        hex_str = format(byte, '02X')
        sub_hex = sbox[hex_str]
        result.append(int(sub_hex, 16))
    return result

# implementation of AddRoundConstant, starts with 01 00 00 00 (hex)
def add_round_constant(word, round_num):
    round_constant = 0x01
    for _ in range(round_num - 1):
        round_constant = xtimes(round_constant)
    
    result = word[:]
    result[0] ^= round_constant
    return result

# logic: rotate, sub, then add round constant
def key_expansion_core(word, round_num, sbox):
    word = rotate_left(word)
    word = sub_bytes_word(word, sbox)
    word = add_round_constant(word, round_num)
    return word

# for 128 bit keys
def key_expansion_128(initial_key, sbox):
    expansion = []
    for b in initial_key:
        expansion.append(b)

    round_num = 1
    while len(expansion) < 176:
        temp = expansion[-4:]

        if len(expansion) % 16 == 0:
            temp = key_expansion_core(temp, round_num, sbox)
            round_num += 1

        previous_word = expansion[-16:-12]
        new_word = []
        for i in range(4):
            new_word.append(temp[i] ^ previous_word[i])

        expansion.extend(new_word)

    return expansion

# for 192 bit keys
def key_expansion_192(initial_key, sbox):
    expansion = []
    for b in initial_key:
        expansion.append(b)

    round_num = 1
    while len(expansion) < 208:
        for j in range(6):
            temp = expansion[-4:]

            if j == 0:
                temp = key_expansion_core(temp, round_num, sbox)
                round_num += 1

            previous_word = expansion[-24:-20]
            new_word = []
            for i in range(4):
                new_word.append(temp[i] ^ previous_word[i])

            expansion.extend(new_word)

    return expansion

# for 256 bit keys
def key_expansion_256(initial_key, sbox):
    expansion = []
    for b in initial_key:
        expansion.append(b)

    round_num = 1
    while len(expansion) < 240:
        for j in range(8):
            temp = expansion[-4:]

            if j == 0:
                temp = key_expansion_core(temp, round_num, sbox)
                round_num += 1
            elif j == 4:
                temp = sub_bytes_word(temp, sbox)

            previous_word = expansion[-32:-28]
            new_word = []
            for i in range(4):
                new_word.append(temp[i] ^ previous_word[i])

            expansion.extend(new_word)

    return expansion


# - Main encryption methods --------

# XOR’s the 128 bit block with the 128 bit key
def add_round_key(state, round_key_words):
    for col in range(4):
        word = round_key_words[col]
        for row in range(4):
            state[row][col] ^= word[row]

# Replaces each 8 bit byte of the 128 bit block with a different 8 bit byte
# I redefined this function because of the issue of working with a hashtable
# that uses strings as keys instead of ints
def sub_bytes(state, sbox):
    for row in range(4):
        for col in range(4):
            byte = state[row][col]
            hex_str = format(byte, '02X')    
            sub_hex = sbox[hex_str]
            state[row][col] = int(sub_hex, 16) 

# hard-coding values into their proper shift positions
def shift_rows(state):
    temp1 = [0] * 4
    temp1[0] = state[1][1]
    temp1[1] = state[1][2]
    temp1[2] = state[1][3]
    temp1[3] = state[1][0]
    for i in range(4):
        state[1][i] = temp1[i]

    temp2 = [0] * 4
    temp2[0] = state[2][2]
    temp2[1] = state[2][3]
    temp2[2] = state[2][0]
    temp2[3] = state[2][1]
    for i in range(4):
        state[2][i] = temp2[i]

    temp3 = [0] * 4
    temp3[0] = state[3][3]
    temp3[1] = state[3][0]
    temp3[2] = state[3][1]
    temp3[3] = state[3][2]
    for i in range(4):
        state[3][i] = temp3[i]

# multiplication by 2 is done using the xtimes() function, and multiplication 
# by 3 is implemented as xtimes(x) XOR x
def mix_columns(state):
    for col in range(4):
        a = [state[row][col] for row in range(4)]

        b = [0] * 4
        for i in range(4):
            b[i] = xtimes(a[i])

        state[0][col] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]
        state[1][col] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]
        state[2][col] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]
        state[3][col] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]


# - Single block encryption --------

# encrypts a block of data
def aes_encrypt_block(block, round_keys, num_rounds, sbox):
    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col * 4 + row]

    # initial AddRoundKey
    round0 = []
    for i in range(4):
        start = i*4
        end = (i+1) * 4
        word = round_keys[start : end]
        round0.append(word)
    add_round_key(state, round0)

    for round_num in range(1, num_rounds):
        # SubBytes
        sub_bytes(state, sbox)

        # ShiftRows
        shift_rows(state)

        # MixColumns
        mix_columns(state)

        # AddRoundKey
        round_words = []
        base = round_num * 4
        for i in range(4):
            start = (base + i) * 4
            end = (base + i + 1) * 4
            word = round_keys[start : end]
            round_words.append(word)
        add_round_key(state, round_words)

    # final round:

    # SubBytes
    sub_bytes(state, sbox)

    # ShiftRows
    shift_rows(state)

    # AddRoundKey
    final_words = []
    base = num_rounds * 4
    for i in range(4):
        start = (base + i) * 4
        end = (base + i + 1) * 4
        word = round_keys[start : end]
        final_words.append(word)
    add_round_key(state, final_words)

    # convert state matrix back to list of 16 bytes
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return result


# - Encryption modes -----------

# EBC encryption mode
def encrypt_ecb(message_bytes, key_bytes, sbox):
    keysize = len(key_bytes)
    if keysize == 16:
        round_keys = key_expansion_128(key_bytes, sbox)
        rounds = 10
    elif keysize == 24:
        round_keys = key_expansion_192(key_bytes, sbox)
        rounds = 12
    elif keysize == 32:
        round_keys = key_expansion_256(key_bytes, sbox)
        rounds = 14
    else:
        raise ValueError("Key must be [16 | 24 | 32] bytes")

    padded = pad_zeros(message_bytes)
    ciphertext = []

    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        encrypted = aes_encrypt_block(block, round_keys, rounds, sbox)
        ciphertext.extend(encrypted)

    return ciphertext


# CBC encryption mode
def encrypt_cbc(message_bytes, key_bytes, sbox):
    keysize = len(key_bytes)
    if keysize == 16:
        round_keys = key_expansion_128(key_bytes, sbox)
        rounds = 10
    elif keysize == 24:
        round_keys = key_expansion_192(key_bytes, sbox)
        rounds = 12
    elif keysize == 32:
        round_keys = key_expansion_256(key_bytes, sbox)
        rounds = 14
    else:
        raise ValueError("Key must be [16 | 24 | 32] bytes")

    padded = pad_zeros(message_bytes)
    ciphertext = []
    prev_cipher = None

    for i in range(0, len(padded), 16):
        block = padded[i:i+16]

        if i == 0:
            encrypted = aes_encrypt_block(block, round_keys, rounds, sbox)
        else:
            # CBC mode: block XOR firstkey XOR prev_cipher
            first_key = []
            for w in range(4):
                start = w*4
                end = (w+1) * 4
                four_bytes = round_keys[start:end]
                for byte in four_bytes:
                    first_key.append(byte)

            modified_block = []
            for j in range(16):
                modified_byte = block[j] ^ first_key[j] ^ prev_cipher[j]
                modified_block.append(modified_byte)

            encrypted = aes_encrypt_block(modified_block, round_keys, rounds, sbox)

        ciphertext.extend(encrypted)
        prev_cipher = encrypted

    return ciphertext


# - Main decryption methods -------
# inverse of original shift rows
def inv_shift_rows(state):
    # Row 0 remains unchanged (no shift)

    # Row 1: shift right by 1
    temp1 = [0] * 4
    temp1[0] = state[1][3]
    temp1[1] = state[1][0]
    temp1[2] = state[1][1]
    temp1[3] = state[1][2]
    for i in range(4):
        state[1][i] = temp1[i]

    # Row 2: shift right by 2
    temp2 = [0] * 4
    temp2[0] = state[2][2]
    temp2[1] = state[2][3]
    temp2[2] = state[2][0]
    temp2[3] = state[2][1]
    for i in range(4):
        state[2][i] = temp2[i]

    # Row 3: shift right by 3 
    temp3 = [0] * 4
    temp3[0] = state[3][1]
    temp3[1] = state[3][2]
    temp3[2] = state[3][3]
    temp3[3] = state[3][0]
    for i in range(4):
        state[3][i] = temp3[i]

# inverse sub bytes using the flipped hashmap
def inv_sub_bytes(state, inv_sbox):
    for row in range(4):
        for col in range(4):
            byte = state[row][col]
            hex_str = format(byte, '02X')
            inv_hex = inv_sbox[hex_str]
            state[row][col] = int(inv_hex, 16)

# inverse of mix columns
# utilizes a fixed inversion matrix
def inv_mix_columns(state):
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]
        
        # convert bytes to polynomial representations
        p0 = byte_to_poly(s0)
        p1 = byte_to_poly(s1)
        p2 = byte_to_poly(s2)
        p3 = byte_to_poly(s3)
        
        # convert coefficients to polynomial form
        coeff_0E = byte_to_poly(0x0E) 
        coeff_0B = byte_to_poly(0x0B)  
        coeff_0D = byte_to_poly(0x0D)  
        coeff_09 = byte_to_poly(0x09)  
        
        # Each new_s.. represents one row of the output column vector resulting from 
        # multiplying the input column vector [p0, p1, p2, p3] by the inverse MixColumns matrix
        new_s0 = add_polynomials(
            add_polynomials(mult_polynomials(p0, coeff_0E), mult_polynomials(p1, coeff_0B)),
            add_polynomials(mult_polynomials(p2, coeff_0D), mult_polynomials(p3, coeff_09))
        )
        
        new_s1 = add_polynomials(
            add_polynomials(mult_polynomials(p0, coeff_09), mult_polynomials(p1, coeff_0E)),
            add_polynomials(mult_polynomials(p2, coeff_0B), mult_polynomials(p3, coeff_0D))
        )
        
        new_s2 = add_polynomials(
            add_polynomials(mult_polynomials(p0, coeff_0D), mult_polynomials(p1, coeff_09)),
            add_polynomials(mult_polynomials(p2, coeff_0E), mult_polynomials(p3, coeff_0B))
        )
        
        new_s3 = add_polynomials(
            add_polynomials(mult_polynomials(p0, coeff_0B), mult_polynomials(p1, coeff_0D)),
            add_polynomials(mult_polynomials(p2, coeff_09), mult_polynomials(p3, coeff_0E))
        )
        
        # assigns the state matrix to the bytes of the generated polynomials
        state[0][col] = poly_to_byte(new_s0)
        state[1][col] = poly_to_byte(new_s1)
        state[2][col] = poly_to_byte(new_s2)
        state[3][col] = poly_to_byte(new_s3)

# - Single block decryption --------
def aes_decrypt_block(cipher_block, round_keys, num_rounds, inv_sbox):
    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = cipher_block[col * 4 + row]

    # initial AddRoundKey 
    round_words = []
    base = num_rounds * 4
    for i in range(4):
        word = round_keys[(base + i) * 4 : (base + i + 1) * 4]
        round_words.append(word)
    add_round_key(state, round_words)

    # InvShiftRows
    inv_shift_rows(state)

    # InvSubBytes
    inv_sub_bytes(state, inv_sbox)

    for round_num in range(num_rounds - 1, 0, -1):
        # AddRoundKey
        round_words = []
        base = round_num * 4
        for i in range(4):
            start = (base + i) * 4 
            end = (base + i + 1) * 4
            word = round_keys[start : end]
            round_words.append(word)
        add_round_key(state, round_words)

        # InvMixColumns
        inv_mix_columns(state)

        # InvShiftRows
        inv_shift_rows(state)

        # InvSubBytes
        inv_sub_bytes(state, inv_sbox)

    # final AddRoundKey
    round_words = []
    for i in range(4):
        start = i*4
        end = (i + 1) * 4
        word = round_keys[start : end]
        round_words.append(word)
    add_round_key(state, round_words)

    decrypted_block = []
    for col in range(4):
        for row in range(4):
            decrypted_block.append(state[row][col])

    return decrypted_block

# - Decryption modes --------

# ECB decryption mode
def decrypt_ecb(cipher_bytes, key, inv_sbox, sbox_map):
    keysize = len(key)
    if keysize == 16:
        round_keys = key_expansion_128(key, sbox_map)
        num_rounds = 10
    elif keysize == 24:
        round_keys = key_expansion_192(key, sbox_map)
        num_rounds = 12
    elif keysize == 32:
        round_keys = key_expansion_256(key, sbox_map)
        num_rounds = 14
    else:
        raise ValueError("Key must be [16 | 24 | 32] bytes")

    plaintext = []

    for i in range(0, len(cipher_bytes), 16):
        block = cipher_bytes[i:i+16]
        decrypted = aes_decrypt_block(block, round_keys, num_rounds, inv_sbox)
        plaintext.extend(decrypted)

    return plaintext

# CBC decryption, main difference is XORing the decrypted block with the
# previous cipher block
def decrypt_cbc(cipher_bytes, key, inv_sbox, sbox_map):
    keysize = len(key)
    if keysize == 16:
        round_keys = key_expansion_128(key, sbox_map)
        num_rounds = 10
    elif keysize == 24:
        round_keys = key_expansion_192(key, sbox_map)
        num_rounds = 12
    elif keysize == 32:
        round_keys = key_expansion_256(key, sbox_map)
        num_rounds = 14
    else:
        raise ValueError("Key must be [16 | 24 | 32] bytes")

    plaintext = []
    prev_cipher_block = [0x00] * 16 

    for i in range(0, len(cipher_bytes), 16):
        block = cipher_bytes[i:i+16]
        decrypted = aes_decrypt_block(block, round_keys, num_rounds, inv_sbox)

        # xor block takes the xor result from the decrypted portion and the prev cipher portion
        # at position j
        xor_block = []
        for j in range(16):
            xor_block.append(decrypted[j] ^ prev_cipher_block[j])

        plaintext.extend(xor_block)
        prev_cipher_block = block 

    return plaintext


# - Utilities ------

# interpet hex data from input files
def read_hex_file(path):
    with open(path, 'r') as f:
        hex_data = f.read().strip()
    return list(bytes.fromhex(hex_data))

# convert bytes to polynomial
def byte_to_poly(byte):
    return [(byte >> i) & 1 for i in range(8)]

# convert polynomial to bytes
def poly_to_byte(poly):
    byte = 0
    for i in range(8):
        byte |= (poly[i] & 1) << i
    return byte

# converts a block into a 4x4 matrix
def block_to_matrix(block):
    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col * 4 + row]
    return state

# adds two polynomials in Z2
def add_polynomials(poly_1, poly_2):
    poly_sum = []
    for i in range(8):
        poly_sum.append(poly_1[i] ^ poly_2[i])
    return poly_sum

# multiplies two polynomials in Z2 and reduces by AES field polynomial
def mult_polynomials(poly_1, poly_2):
    result = [0] * 15
    
    for i in range(8):
        for j in range(8):
            result[i + j] ^= poly_1[i] & poly_2[j]
    
    for i in range(14, 7, -1):
        if result[i]:
            for j in range(9):
                if j == 8 or j == 4 or j == 3 or j == 1 or j == 0:
                    result[i - 8 + j] ^= 1
    
    poly_to_return = []
    for i in range(8):
        poly_to_return.append(result[i])
    
    return poly_to_return

# xtimes function for AES field
def xtimes(byte_value):
    result = (byte_value << 1) & 0xFF
    if byte_value & 0x80:
        result ^= 0x1B
    return result
    
# pad our data with 0s
def pad_zeros(data):
    padding_len = 16 - (len(data) % 16)
    if padding_len == 16:
        return data
    return data + [0x00] * padding_len

# - Entry point of the program --------
def main():
    if len(sys.argv) != 4:
        print("Usage: python aes_project.py <encrypt|decrypt> <key_file> <p-text OR c-text_file>")
        return

    mode = sys.argv[1].lower()
    keyfile = sys.argv[2]
    msgfile = sys.argv[3]

    try:
        key = read_hex_file(keyfile)
        data = read_hex_file(msgfile)

        if mode == "encrypt":
            ecb_cipher = encrypt_ecb(data, key, sbox_map)
            cbc_cipher = encrypt_cbc(data, key, sbox_map)

            print("------------")
            print("ECB Ciphertext:") 
            print(bytes(ecb_cipher).hex())
            print("------------")
            print("CBC Ciphertext:") 
            print(bytes(cbc_cipher).hex())
            print("------------")

        elif mode == "decrypt":
            ecb_plain = decrypt_ecb(data, key, inverse_sbox_map, sbox_map)
            cbc_plain = decrypt_cbc(data, key, inverse_sbox_map, sbox_map)

            print("------------")
            print("ECB Plaintext:") 
            print(bytes(ecb_plain).hex())
            print("------------")
            print("CBC Plaintext:") 
            print(bytes(cbc_plain).hex())
            print("------------")

        else:
            print("Invalid mode. Use 'encrypt' or 'decrypt'")

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
