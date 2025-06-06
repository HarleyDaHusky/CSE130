key = b'\xac\x7f\x08\xcc'
message = "Encryption is the foundation of secure communication, ensuring that only authorized parties can read confidential information. By applying cryptographic techniques, sensitive data remains protected from potential attackers."

def vigenere_encrypt(plaintext, key):
    key_len = len(key)
    return bytes([plaintext[i] ^ key[i % key_len] for i in range(len(plaintext))])

plaintext = message.encode('utf-8') # https://www.w3schools.com/charsets/ref_html_utf8.asp
ciphertext = vigenere_encrypt(plaintext, key)

hex_ciphertext = ciphertext.hex() # https://www.geeksforgeeks.org/python-convert-bytearray-to-hexadecimal-string/

with open('encrypted_message_hex.txt', 'w') as f:
    f.write(hex_ciphertext)