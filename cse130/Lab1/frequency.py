from collections import Counter

def compute_freq_table(ciphertext, max_key_len):
    freq_table = {}
    for key_len in range(1, max_key_len + 1):
        sum_sq = 0
        for k in range(key_len):
            stream_j = ciphertext[k::key_len]
            stream_len = len(stream_j)
            freq = Counter(stream_j)
            for byte in freq:
                sum_sq += (freq[byte] / stream_len) ** 2
        freq_table[key_len] = sum_sq / key_len
    for key_len, value in freq_table.items():
        print(f"Key Length: {key_len} - Frequency Sum of Squares: {value}")

ciphertext = b'\xe9\x11k\xbe\xd5\x0f|\xa5\xc3\x11(\xa5\xdf_|\xa4\xc9_n\xa3\xd9\x11l\xad\xd8\x16g\xa2\x8c\x10n\xec\xdf\x1ak\xb9\xde\x1a(\xaf\xc3\x12e\xb9\xc2\x16k\xad\xd8\x16g\xa2\x80_m\xa2\xdf\nz\xa5\xc2\x18(\xb8\xc4\x1e|\xec\xc3\x11d\xb5\x8c\x1e}\xb8\xc4\x10z\xa5\xd6\x1al\xec\xdc\x1ez\xb8\xc5\x1a{\xec\xcf\x1ef\xec\xde\x1ai\xa8\x8c\x1cg\xa2\xca\x16l\xa9\xc2\x0ba\xad\xc0_a\xa2\xca\x10z\xa1\xcd\x0ba\xa3\xc2Q(\x8e\xd5_i\xbc\xdc\x13q\xa5\xc2\x18(\xaf\xde\x06x\xb8\xc3\x18z\xad\xdc\x17a\xaf\x8c\x0bm\xaf\xc4\x11a\xbd\xd9\x1a{\xe0\x8c\x0cm\xa2\xdf\x16|\xa5\xda\x1a(\xa8\xcd\x0bi\xec\xde\x1ae\xad\xc5\x11{\xec\xdc\rg\xb8\xc9\x1c|\xa9\xc8_n\xbe\xc3\x12(\xbc\xc3\x0bm\xa2\xd8\x16i\xa0\x8c\x1e|\xb8\xcd\x1cc\xa9\xde\x0c&'
max_key_len = 20 #1-20
compute_freq_table(ciphertext, max_key_len)


# Function compute_freq_table(ciphertext, max_key_len):
#     Iterate key_len from 1 to max_key_len:
#     Initialize freq_table = dict(key=key length: value=sum of freq square)
#     Iterate k from 1 to key_len:
#     stream_j = Extract stream from ciphertext
#     stream_len = length of the stream_j (as a byte array)
#     freq = Count number of occurrences of each byte in stream_j
#     sum_sq += Sum (freq[b] / stream_len)**2 for each b in stream_j
#     freq_table[key_len] = sum_sq / key_len
# Print freq_table