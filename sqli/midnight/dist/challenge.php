<?php

$conn = new mysqli('db', 'root', 'password', 'challenge_db');
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$username = $_GET['username'] ?? '';
$message = '';

if ($username !== '') {
    $sql = "SELECT * FROM users WHERE username = '$username'";
    $result = $conn->query($sql);
    if ($result && $result->num_rows > 0) {
        $message = "<span class='success'>User found!</span>";
    } else {
        $message = "<span class='error'>User not found!</span>";
    }
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Midnight SQL Injection Challenge</title>
    <style>
        body {
            background: linear-gradient(120deg, #232526, #414345);
            color: #fff;
            font-family: 'Segoe UI', Arial, sans-serif;
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: rgba(30, 30, 40, 0.95);
            padding: 2.5rem 2rem 2rem 2rem;
            border-radius: 18px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            min-width: 340px;
            max-width: 90vw;
        }
        h1 {
            text-align: center;
            font-size: 2rem;
            margin-bottom: 1.2rem;
            letter-spacing: 1px;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        input[type="text"] {
            padding: 0.7rem 1rem;
            border-radius: 8px;
            border: none;
            font-size: 1rem;
            background: #232526;
            color: #fff;
            outline: none;
            transition: box-shadow 0.2s;
        }
        input[type="text"]:focus {
            box-shadow: 0 0 0 2px #6a82fb;
        }
        button {
            padding: 0.7rem 1rem;
            border-radius: 8px;
            border: none;
            background: linear-gradient(90deg, #6a82fb, #fc5c7d);
            color: #fff;
            font-size: 1rem;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: linear-gradient(90deg, #fc5c7d, #6a82fb);
        }
        .result {
            margin-top: 1.2rem;
            text-align: center;
            font-size: 1.1rem;
        }
        .success { color: #6affb2; }
        .error { color: #ff6a6a; }
        .desc {
            margin-bottom: 1.5rem;
            color: #bdbdbd;
            font-size: 1rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Midnight SQL Injection</h1>
        <div class="desc">
            Can you leak the admin password ?<br>
        </div>
        <form method="get" autocomplete="off">
            <input type="text" name="username" placeholder="Enter username" value="<?= htmlspecialchars($username) ?>" autofocus required />
            <button type="submit">Check User</button>
        </form>
        <?php if ($username !== ''): ?>
            <div class="result"><?= $message ?></div>
        <?php endif; ?>
    </div>
</body>
</html> 