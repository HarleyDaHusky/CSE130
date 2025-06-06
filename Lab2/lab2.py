# https://pycryptodome.readthedocs.io/
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import random
import time

BLOCK_SIZE = 16  # AES block size in bytes

def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def corrupt_data(data, num_bits=None):
    # Randomly flip multiple bits in the given data
    corrupted_data = bytearray(data)
    num_bits = num_bits or random.randint(1, 8)  # Randomize the number of bits to flip (1 to 8)
    for _ in range(num_bits): #ignoring loop index
        byte_index = random.randint(0, len(corrupted_data) - 1)
        bit_index = random.randint(0, 7)
        corrupted_data[byte_index] ^= (1 << bit_index)  # Corrupt by XORING a random bit with a bitmask
    return bytes(corrupted_data)

# ECB Mode
def ecb_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data)
    return cipher.encrypt(padded_data)

def ecb_decrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

def corrupt_ecb_encrypt(key, data):
    encrypted_data = ecb_encrypt(key, data)
    return corrupt_data(encrypted_data)

# CBC Mode
def cbc_encrypt(key, data):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data)
    return iv + cipher.encrypt(padded_data)

def cbc_decrypt(key, data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[BLOCK_SIZE:]))

def corrupt_cbc_encrypt(key, data):
    encrypted_data = cbc_encrypt(key, data)
    return corrupt_data(encrypted_data)

# OFB Mode
def ofb_encrypt(key, data):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return iv + cipher.encrypt(data)

def ofb_decrypt(key, data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.decrypt(data[BLOCK_SIZE:])

def corrupt_ofb_encrypt(key, data):
    encrypted_data = ofb_encrypt(key, data)
    return corrupt_data(encrypted_data)

# CTR Mode
def ctr_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CTR)  # Create AES cipher in CTR mode
    ciphertext = cipher.encrypt(data)   # Encrypt the data
    return cipher.nonce + ciphertext    # Prepend the nonce to the ciphertext

def ctr_decrypt(key, data):
    nonce = data[:BLOCK_SIZE // 2]      # Extract the nonce (first 8 bytes)
    ciphertext = data[BLOCK_SIZE // 2:] # Extract the ciphertext
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)  # Create AES cipher with the same nonce
    return cipher.decrypt(ciphertext)   # Decrypt the ciphertext

def corrupt_ctr_encrypt(key, data):
    encrypted_data = ctr_encrypt(key, data)
    return corrupt_data(encrypted_data)

# BMP Image Processing
def read_bmp(file_path):
    with open(file_path, "rb") as f:
        header = f.read(54)  # BMP header is 54 bytes
        data = f.read()
    return header, data

def write_bmp(file_path, header, data):
    with open(file_path, "wb") as f:
        f.write(header)
        f.write(data)

def test_ecb(input_image, output_encrypted, output_decrypted, key):
    print("Testing ECB Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    start_time = time.time()
    encrypted_data = ecb_encrypt(key, data)
    end_time = time.time()
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")
    print(f"ECB Encryption Time: {end_time - start_time:.6f} seconds")

    # Decrypt
    start_time = time.time()
    decrypted_data = ecb_decrypt(key, encrypted_data)
    end_time = time.time()
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")
    print(f"ECB Decryption Time: {end_time - start_time:.6f} seconds")

def test_corrupt_ecb(input_image, output_encrypted, output_decrypted, key):
    print("Testing Corrupted ECB Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    encrypted_data = corrupt_ecb_encrypt(key, data)
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")

    # Decrypt
    decrypted_data = ecb_decrypt(key, encrypted_data)
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")

def test_cbc(input_image, output_encrypted, output_decrypted, key):
    print("Testing CBC Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    start_time = time.time()
    encrypted_data = cbc_encrypt(key, data)
    end_time = time.time()
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")
    print(f"CBC Encryption Time: {end_time - start_time:.6f} seconds")

    # Decrypt
    start_time = time.time()
    decrypted_data = cbc_decrypt(key, encrypted_data)
    end_time = time.time()
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")
    print(f"CBC Decryption Time: {end_time - start_time:.6f} seconds")

def test_corrupt_cbc(input_image, output_encrypted, output_decrypted, key):
    print("Testing Corrupted CBC Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    encrypted_data = corrupt_cbc_encrypt(key, data)
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")

    # Decrypt
    decrypted_data = cbc_decrypt(key, encrypted_data)
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")

def test_ofb(input_image, output_encrypted, output_decrypted, key):
    print("Testing OFB Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    start_time = time.time()
    encrypted_data = ofb_encrypt(key, data)
    end_time = time.time()
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")
    print(f"OFB Encryption Time: {end_time - start_time:.6f} seconds")

    # Decrypt
    start_time = time.time()
    decrypted_data = ofb_decrypt(key, encrypted_data)
    end_time = time.time()
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")
    print(f"OFB Decryption Time: {end_time - start_time:.6f} seconds")

def test_corrupt_ofb(input_image, output_encrypted, output_decrypted, key):
    print("Testing Corrupted OFB Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    encrypted_data = corrupt_ofb_encrypt(key, data)
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")

    # Decrypt
    decrypted_data = ofb_decrypt(key, encrypted_data)
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")

def test_ctr(input_image, output_encrypted, output_decrypted, key):
    print("Testing CTR Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    start_time = time.time()
    encrypted_data = ctr_encrypt(key, data)
    end_time = time.time()
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")
    print(f"CTR Encryption Time: {end_time - start_time:.6f} seconds")

    # Decrypt
    start_time = time.time()
    decrypted_data = ctr_decrypt(key, encrypted_data)
    end_time = time.time()
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")
    print(f"CTR Decryption Time: {end_time - start_time:.6f} seconds")

def test_corrupt_ctr(input_image, output_encrypted, output_decrypted, key):
    print("Testing Corrupted CTR Mode...")
    header, data = read_bmp(input_image)

    # Encrypt
    encrypted_data = corrupt_ctr_encrypt(key, data)
    write_bmp(output_encrypted, header, encrypted_data)
    print(f"Encrypted image saved to {output_encrypted}")

    # Decrypt
    decrypted_data = ctr_decrypt(key, encrypted_data)
    write_bmp(output_decrypted, header, decrypted_data)
    print(f"Decrypted image saved to {output_decrypted}")

if __name__ == "__main__":
    key = b"i1andfd8emidr6no"
    input_image = "test_image.bmp"
    # Corruption tests commented out after use in Task 3
    test_ecb(input_image, "ecb_encrypted.bmp", "ecb_decrypted.bmp", key)
    print()
    #test_corrupt_ecb(input_image, "ecb_corrupt_encrypted3.bmp", "ecb_corrupt_decrypted3.bmp", key)
    print()
    test_cbc(input_image, "cbc_encrypted.bmp", "cbc_decrypted.bmp", key)
    print()
    #test_corrupt_cbc(input_image, "cbc_corrupt_encrypted3.bmp", "cbc_corrupt_decrypted3.bmp", key)
    print()
    test_ofb(input_image, "ofb_encrypted.bmp", "ofb_decrypted.bmp", key)
    print()
    #test_corrupt_ofb(input_image, "ofb_corrupt3_encrypted.bmp", "ofb_corrupt_decrypted3.bmp", key)
    print()
    test_ctr(input_image, "ctr_encrypted.bmp", "ctr_decrypted.bmp", key)
    print()
    #test_corrupt_ctr(input_image, "ctr_corrupt_encrypted3.bmp", "ctr_corrupt_decrypted3.bmp", key)
    print()
