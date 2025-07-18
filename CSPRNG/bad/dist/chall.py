import random

_state = None

def generate_seed() -> int:

    global _state
    _state = random.randint(1, 255)
    return _state

def rand_word() -> int:
    global _state
    _state = (_state * 3) % 256
    return _state

FLAG = b"flag{i_am_your_lovely_flag}"

if __name__ == '__main__':
    generate_seed()

    ciphertext = []
    for byte in FLAG:
        rnd = rand_word()
        ciphertext.append(rnd ^ byte)

    hex_output = bytes(ciphertext).hex()
    print(hex_output)
