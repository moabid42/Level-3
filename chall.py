import string

MAX = 30

def chall():
    import sys
    code = input()
    assert len(code) <= MAX
    if any(i in code for i in ["import", "exec", "eval", "system"]) \
        or any(i in '_\"[]{}' for i in code) \
        or any(i not in string.printable for i in code):
        sys.exit()
    sys.stdout = "sys.stdout"
    del sys
    exec(code)

chall()
