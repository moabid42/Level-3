import string

MAX = 50

def chall():
    import sys
    code = input()
    assert len(code) <= MAX
    if any(i in code for i in ["import", "exec", "eval", "system"]) \
        or any(i in '_\"[]{}' for i in code) \
        or any(i not in string.printable for i in code):
        sys.exit()
    # sys.stdout = "sys.stdout"
    del sys
    print(exec(code))

chall()


'''
global a;a=globals();chall()
a.update(MAX=9999);chall()
open('/Users/nil/Documents/Level-3/jails/py/noname/dist/chall.py', 'a').write('i')
'''
# open('/Users/nil/Documents/Level-3/jails/py/noname/dist/chall.py', 'a').write('b')ab