from flask import Flask, request, render_template_string, abort
import sqlite3
import os

app = Flask(__name__)

os.makedirs('data', exist_ok=True)
DB_PATH = 'data/users.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        secret TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (1, 'alice', 'alice@example.com')")
    c.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (2, 'bob', 'bob@example.com')")
    c.execute("INSERT OR IGNORE INTO secrets (id, secret) VALUES (1, 'flag{error_based_secret}')")
    conn.commit()
    conn.close()

init_db()

HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error-based SQLi Challenge</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .container { max-width: 500px; margin: 60px auto; background: #fff; padding: 30px 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { text-align: center; }
        form { display: flex; gap: 10px; margin-bottom: 20px; }
        input[type="text"] { flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; background: #007bff; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #f0f0f0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Error-based SQLi Challenge</h1>
        <form method="GET">
            <input type="text" name="id" placeholder="Enter user ID..." required />
            <button type="submit">Lookup</button>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        {% if result %}
        <table>
            <tr><th>ID</th><th>Username</th><th>Email</th></tr>
            <tr><td>{{ result[0] }}</td><td>{{ result[1] }}</td><td>{{ result[2] }}</td></tr>
        </table>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    user_id = request.args.get('id', '')
    result = None
    error = None
    if user_id:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
            c.execute(query)
            result = c.fetchone()
            conn.close()
        except Exception as e:
            error = str(e)
    return render_template_string(HTML, result=result, error=error)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5555) 