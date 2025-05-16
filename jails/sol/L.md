# Python jail
inside the command line we do {{''.class.base.subclasses()[405](['cat','flag.txt'], stdout=PIPE).communicate()[0]}}

SOURCES:
server side template injection.

https://www.youtube.com/watch?v=SN6EVIG4c-0&t=315s

after that i listed all the classes (i was always using ‘inspect button on the webbrowser to see the output), with the command ‘’.class.base.subclasses() → i got the list of subclasses. 
I asked GPT:
There is so many subclasses when i list them, how can i understand which are useful and which are not

Useful‑class heuristics (quick triage)

Executes commands – any subclass whose name hints at process spawning: Popen, call, run, subprocess.*.
Reads/Writes files – look for _io.*, TextIOWrapper, FileIO, BufferedReader, ZipFile, TarFile, Path, open.*.
Imports modules / holds globals – wrapper classes such as warnings.catch_warnings, logging.*, importlib.*; their methods often expose __globals__ with os, sys.
Introspection helpers – function, method, code, frame, traceback, inspect.*; they leak source, locals, or allow eval.
Network / crypto – urllib.*, http.client.*, ssl.*, socket.* can exfiltrate data.
Framework internals – werkzeug.*, flask.*, jinja2.*; may hold secret keys or request objects.

then i wantched a video on the subprocess:
https://www.youtube.com/watch?v=yOBBq3dl0to

and i write a scirpt in python to spot the place of the subporcess.Popen , which is 405

and then i wrote the commands to run as a shell scirpt on the server side and got:

---------------------------------------------
YouTube
PwnFunction
Server-Side Template Injections Explained
Image
YouTube
Luke May
Python 3 Subprocess Module - Run terminal commands from a Python pr...

# fiberglass
i searched on how can you bypass chmod restrictions and found out that i can execute file with base64 ./flag and i'll get Q1RGe3JhY2VfY29uZGl0aW9uX3N5bWxpbmt9Cg==
then i decoded it in terminal using 
print 'Q1RGe3JhY2VfY29uZGl0aW9uX3N5bWxpbmt9Cg==' | base64 and i got the output CTF{race_condition_symlink}
