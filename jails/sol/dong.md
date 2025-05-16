bash/fiberglass

I initially came up with an idea of `'l''e''s''s' flag`
but `less` command was not found. Next, I tried googling but there were not many resources so I asked deepseek and it gave me a solution of `base64 flag`
After that, I remembered similar challenges from pwn.college and found out `as` command also works. Learned cool ideas from `https://pwn.college/fundamentals/program-misuse/`



js/vm

I have zero experience on javascript so I used copilot for code explanation. But it also showed me how to exploit it. `this` keyword refers `context` which is global object so this[flag] would print the flag. To bypass restrictions,
`"this[String.fromCharCode(102, 108, 97, 103)]"` and
`"this[\"\\x66\\x6c\\x61\\x67\"]"` works.

Full solution would be 
```curl -X POST http://localhost:3000/eval \
-H "Content-Type: application/json" \
-d '{"code":"this[String.fromCharCode(102, 108, 97, 103)]"}'
```



js/wtf

Similar to the other js chall, copilot gave me how to get the flag using `jsfuck.com`.



py/small

I couldn't fully understand the whole line of code but I briefly understood it's limiting the length of input to 42, and only using `print` as builtin. So I googled `pyjail eval builtin print` and luckily found `https://github.com/jailctf/pyjail-collection/tree/main/chals/minijail`, which is very similar to this challenge.
Full solution : `[b:=print.__self__,b.exec(b.input())] -> b.__import__('os').system('sh')` The first part lets variable `b` to use full builtins, then the next part is to run sh.



py/portal

First, I needed to understand how the code works since I never used flask before. But after spending some time, I was still lost so tried to remember what happened during the discord meeting. I remembered SSTI and  guessed this is sth related to it.
After reading many articles from googling, I found `render_template_string` function have exploit.
Jinja2 uses double curly brases `{{ }}` as expression to render, not just payload from client. Since we know the location of the flag file the solution would be
`{{ [].__class__.__base__.__subclasses__()[99].get_data(".", "flag.txt") }}` for python version 3.9
reference: `https://payatu.com/blog/server-side-template-injectionssti/`, `https://semgrep.dev/docs/cheat-sheets/flask-xss`, `https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti`



py/noname

I spent so much time to call shell but could not figured it out.
I found similar challenge from `https://github.com/jailctf/pyjail-collection/tree/main/chals/exceptional-pyjail` and was able to read dummy flag file.
I tried :
1. Calling `input()` to bypass limit 30 restriction and open the flag file but failed due to stdout setting.
2. Calling `input()` and set the stdout back to normal. -> I tried similar approaches from github repos but none of them worked.
My conclusion is there is difference between a) reading a file and then calling `exec()` function and
                                                                                       b) calling `exec()` function and then reading a file.
Really look forward to the solution lecture.

My solution: int(open('flag.txt').read())