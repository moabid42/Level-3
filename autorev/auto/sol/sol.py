from capstone import *
from z3 import *

for n in range(100):
    print(n, end=' ')
    with open(f'../dev/auto/challenge_{n}', 'rb') as f:
        data = f.read()

    start = 0x3010
    cs = Cs(CS_ARCH_X86, CS_MODE_64)

    insts = []
    i = 0
    while True:
        addr = start + i
        addr = int.from_bytes(data[addr:addr+8], 'little')
        if addr == 0:
            break
        if addr > 0x10000:
            break

        func = data[addr:addr+100]
        func_insts = []
        for inst in cs.disasm(func, addr):
            func_insts.append(inst)
            if inst.mnemonic == 'ret':
                break
        
        for inst in func_insts[1:-2]:
            # print(f'0x{inst.address:x}:\t{inst.mnemonic}\t{inst.op_str}')
            insts.append(inst)
        i += 8
    
    s = Solver()
    inputs = [z3.BitVec(f'input_{i}', 16) for i in range(16)]

    for inp in inputs:
        s.add(Or(
            And(inp >= 0x41, inp <= 0x5a), # A-Z
            And(inp >= 0x61, inp <= 0x7a), # a-z
            And(inp >= 0x30, inp <= 0x39), # 0-9
            inp == ord('+'),
            inp == ord('/'),
        ))
    eax = None
    edx = None
    offset = 0
    for inst in insts:
        inst_str = f'{inst.mnemonic} {inst.op_str}' 
        if inst_str == 'mov rax, qword ptr [rbp - 0x18]':
            offset = 0
        elif inst_str.startswith('add rax,'):
            offset = int(inst_str.split(',')[1].strip(), 0)
        elif 'byte ptr [rax]' in inst_str:
            reg = inst_str.split(' ')[1].split(',')[0]
            if reg == 'eax':
                eax = inputs[offset]
            elif reg == 'edx':
                edx = inputs[offset]
        elif inst_str == 'movsx edx, al':
            edx = eax
        elif inst_str == 'movzx eax, dx':
            eax = edx
        # conditions
        elif inst_str == 'imul eax, edx':
            eax = eax * edx
        elif inst_str == 'add eax, edx':
            eax = eax + edx
        elif inst_str == 'xor eax, edx':
            eax = eax ^ edx
        elif inst_str == 'sub edx, eax':
            edx = edx - eax
        elif inst_str.startswith('cmp eax,'):
            cmp_val = int(inst_str.split(',')[1].strip(), 0)
            s.add(eax == cmp_val)
        elif inst_str.startswith('cmp edx,'):
            cmp_val = int(inst_str.split(',')[1].strip(), 0)
            s.add(edx == cmp_val)

    if s.check() == sat:
        m = s.model()
        pwd = ''.join([chr(m[i].as_long()) for i in inputs]).encode()
        print(pwd)
    else:
        print('no solution')
