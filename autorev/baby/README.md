# Z3 Baby Steps Challenge

## Description

Before taking big steps, we need to take **baby steps**.

This challenge is designed to be a gentle introduction to using [Z3](https://github.com/Z3Prover/z3), a powerful theorem prover developed by Microsoft. The goal is to **solve it on your own**, without relying on external solutions (One search will show the solution, but that's is not the goal). So please while it's tempting to Google for hints, **resist the urge**, doing so will just f*ck up your learning and make future challenges much more difficult.

Treat this as a learning opportunity. The skills you build here will be essential for more complex symbolic execution and constraint-solving problems later.

---

## Challenge Link

[Hack The Box - Baby Steps](https://app.hackthebox.com/challenges/409)

---

## Tips

- Use the **Z3 Python bindings** to model and solve constraints.
- Start simple: define variables, add constraints, and ask Z3 to solve them.
- Read Z3 documentation or explore official examples if you're completely new — but don't look up direct solutions to the challenge.

---

# Materials
[Documentation from Microsoft](https://microsoft.github.io/z3guide/docs/logic/intro)

##  Template
```py
from z3 import *

# Define symbolic variables (you'll need to figure out how many and what types)
# For example, if the challenge works on a string of 8 characters:
chars = [BitVec(f'char_{i}', 8) for i in range(8)]

# Create the solver instance
s = Solver()

# Add constraints here
# Example: s.add(chars[0] + chars[1] == 150)
# You'll need to reverse the logic in the binary or challenge file to figure these out.

# Constraint: All characters should be printable (optional, but helpful)
for c in chars:
    s.add(c >= 32, c <= 126)

# Solve the constraints
if s.check() == sat:
    model = s.model()
    result = ''.join([chr(model[c].as_long()) for c in chars])
    print(f"[+] Solution: {result}")
else:
    print("[-] No solution found.")
```

