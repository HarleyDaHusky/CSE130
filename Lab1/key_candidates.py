from collections import Counter # https://stackoverflow.com/questions/12452678/fastest-way-to-count-number-of-occurrences-in-a-python-list
                                # for line 16

def recover_candidate_keys(ciphertext, key_len):
    candidate_keys = []
    #     Initialize candidate_keys --- Psuedocode
    #     Iterate j from 0 to key_len:
    #     stream_j = Extract stream from ciphertext // see next slide for stream
    #     freq = Count number of occurrences of each byte in stream_j
    #     top_bytes = Select the top candidates from the sorted freq
    #     cand_key = Recover top_bytes with COMMON_LETTERS
    #     Append cand_key to candidate_keys
    # Iterate j from 0 to key_len
    for j in range(key_len):
        stream_j = ciphertext[j::key_len]
        freq = Counter(stream_j) # from the module collections to count number of occurrences of each byte in stream
        top_bytes = [byte for byte, count in freq.most_common(5)]  # including limiter due to too many possible outputs, previous attempt without limiter crashed at 7.4 million lines and first two letters "Dy..."
        cand_key = [byte ^ ord(letter) for byte in top_bytes for letter in [' ', 'e']]
        candidate_keys.append(cand_key)
    return candidate_keys

def try_all_candidate_keys(ciphertext, candidate_keys, output_file, current_key=[], depth=0):
    # Iterate over all possible combinations of candidate keys
    # Function try_all_candidate_keys(ciphertext, candidate_keys):
    #     Iterate candidate_keys:
    #     decrypted_message = decrypt(ciphertext, key)
    #     Print decrypted_message
    if depth == len(candidate_keys):
        key = bytes(current_key)
        decrypted_message = decrypt(ciphertext, key)
        try:
            readable_message = decrypted_message.decode('utf-8') # https://www.w3schools.com/charsets/ref_html_utf8.asp
            with open(output_file, 'a') as f:
                f.write(f"Key: {key} - Message: {readable_message}\n")
        except UnicodeDecodeError: # Basically passes those that dont make sense after being de-encrypted
            pass 
    else:
        for key_byte in candidate_keys[depth]:
            try_all_candidate_keys(ciphertext, candidate_keys, output_file, current_key + [key_byte], depth + 1)

def decrypt(ciphertext, key):
    key_len = len(key)
    return bytes([ciphertext[i] ^ key[i % key_len] for i in range(len(ciphertext))]) # XOR operation

ciphertext = b'\xe9\x11k\xbe\xd5\x0f|\xa5\xc3\x11(\xa5\xdf_|\xa4\xc9_n\xa3\xd9\x11l\xad\xd8\x16g\xa2\x8c\x10n\xec\xdf\x1ak\xb9\xde\x1a(\xaf\xc3\x12e\xb9\xc2\x16k\xad\xd8\x16g\xa2\x80_m\xa2\xdf\nz\xa5\xc2\x18(\xb8\xc4\x1e|\xec\xc3\x11d\xb5\x8c\x1e}\xb8\xc4\x10z\xa5\xd6\x1al\xec\xdc\x1ez\xb8\xc5\x1a{\xec\xcf\x1ef\xec\xde\x1ai\xa8\x8c\x1cg\xa2\xca\x16l\xa9\xc2\x0ba\xad\xc0_a\xa2\xca\x10z\xa1\xcd\x0ba\xa3\xc2Q(\x8e\xd5_i\xbc\xdc\x13q\xa5\xc2\x18(\xaf\xde\x06x\xb8\xc3\x18z\xad\xdc\x17a\xaf\x8c\x0bm\xaf\xc4\x11a\xbd\xd9\x1a{\xe0\x8c\x0cm\xa2\xdf\x16|\xa5\xda\x1a(\xa8\xcd\x0bi\xec\xde\x1ae\xad\xc5\x11{\xec\xdc\rg\xb8\xc9\x1c|\xa9\xc8_n\xbe\xc3\x12(\xbc\xc3\x0bm\xa2\xd8\x16i\xa0\x8c\x1e|\xb8\xcd\x1cc\xa9\xde\x0c&'
key_len = 4 #4,8,12,16,20
candidate_keys = recover_candidate_keys(ciphertext, key_len)
try_all_candidate_keys(ciphertext, candidate_keys, 'decrypted_messages.txt')