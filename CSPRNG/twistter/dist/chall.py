import random
import os

FLAG = b"easyctf{p0lyn0m14l_p53ud0_r4nd0m}"
L = len(FLAG)

# Seed PRNG states
X0 = random.getrandbits(16)
X1 = random.getrandbits(16)

# Generate outputs
leak_bytes = []
cipher_bytes = []
for _ in range(L):
    X2 = (X1 + X0) & 0xFFFF
    keystream = X2 & 0xFF
    leak = (X2 >> 8) & 0xFF
    leak_bytes.append(leak)
    cipher_bytes.append(keystream ^ FLAG[_])
    X0, X1 = X1, X2

# Print hex strings
print(bytes(leak_bytes).hex())   # leak: high bytes
print(bytes(cipher_bytes).hex()) # ciphertext: flag XOR keystream
