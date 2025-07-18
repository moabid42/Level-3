#!/usr/bin/env python3
# ===== chall_cryptoclock.py =====
import time
import random
import sys

"""
CTF Challenge: "Cryptoclock"

This script simulates a server that:
  1. Seeds Python's random with the current Unix time.
  2. Generates a pseudorandom key of the same length as the flag.
  3. XORs the flag with the key and prints the hex ciphertext.
  4. Re-seeds with the same time and XORs a known plaintext of 'A's,
     printing that oracle response as hex.

Students must brute-force the timestamp seed using the oracle to recover
the seed, then decrypt the ciphertext to obtain the flag.
"""

# --- Configuration ---
FLAG = b"cryptoclock{t1m3_1s_n0t_s0_r4nd0m}"
KNOWN_PT = b"A" * len(FLAG)
LENGTH = len(FLAG)

# --- Challenge Generation ---
# Seed with current time
seed = int(time.time())
random.seed(seed)

# Generate key and encrypt flag
key = bytes(random.randint(0, 255) for _ in range(LENGTH))
encrypted_flag = bytes(f ^ k for f, k in zip(FLAG, key))

# Re-seed and generate oracle response for KNOWN_PT
random.seed(seed)
key2 = bytes(random.randint(0, 255) for _ in range(LENGTH))
oracle_response = bytes(p ^ k for p, k in zip(KNOWN_PT, key2))

# Output hex strings
print(encrypted_flag.hex())    # Encrypted flag
print(oracle_response.hex())   # Oracle response for known plaintext
