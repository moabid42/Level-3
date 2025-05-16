# fiberglass
built the image and ran the container. checked on which port i can reach the frontend. 

Executed multiple command but realized from the php code I am very limited due to the input limitation. Only valid Commands Made from "fiberglass".

Found that the ls and ls la / work
found the flag file, tried to read and execute it, thought it might be a script.

I realized that I am limited to literal filenames
cannot use wildcards (*) to probe content
cannot escape with cat, head, etc.
But can read file metadata with ls -l flag


only working command so far were ls.
No wildcards (*), redirection, or alternate paths work.
No helper binary.


What was Working after many tries:
ls, and ls -la were functional.

tried "file flag"
This returned something like: flag: ASCII text
confirmed: that The flag file is a plain text file.


". flag" executed the contents of flag as a Bash script. Since it wasn't valid Bash (just the flag string), Bash tried to "run" the flag as a command, which failed, but echoed the string back in the error. That error message revealed the entire flag.

# vm
here is the first one of the JS jails, luckily my previous background in Frontend helped alot and I found this one way easier than the bash jail.

Setup the Node.js server installed express and tested the app. Found out that  a flag variable was defined in the sandbox, 
but direct access to it was blocked using a regular expression filter that disallowed keywords such as flag and others. 

Submissions were passed to vm.runInContext, and any code containing those patterns was rejected. Initial test using Object.getOwnPropertyNames(this) revealed that flag was indeed present in the execution context.

 tries to use this["flag"] were blocked due to the filter, but the dynamic nature of JS allowed for string concatenation. JS is indeed a funny language and allows such leaks due to its dynamic nature. by creating the key "flag" at runtime with "f" + "l" + "a" + "g", the code this["f" + "l" + "a" + "g"] successfully bypassed the filter and accessed the variable. The server returned the flag’s value. 

another superficial restrictions that doesn't fully prevent access to sensitive data when indirect evaluation or property access is possible due to JS's flexibility in accessing properties dynamically.
I hope I had more time invested, I really enjoyed it. even though at was sometimes frustrating.
