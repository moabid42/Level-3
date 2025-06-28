<?php
// Database connection settings
$host = getenv('MYSQL_HOST') ?: 'db';
$db   = getenv('MYSQL_DATABASE') ?: 'testdb';
$user = getenv('MYSQL_USER') ?: 'root';
$pass = getenv('MYSQL_PASSWORD') ?: 'example';

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
}

// Get the 'user' parameter from the URL
$username = isset($_GET['user']) ? $_GET['user'] : '';

// Vulnerable SQL query (no sanitization!)
$sql = "SELECT id, username, email FROM users WHERE username = '$username'";
$result = $conn->query($sql);

if ($result) {
    if ($result->num_rows > 0) {
        echo '<table><tr><th>ID</th><th>Username</th><th>Email</th></tr>';
        while ($row = $result->fetch_assoc()) {
            echo '<tr>';
            echo '<td>' . htmlspecialchars($row['id']) . '</td>';
            echo '<td>' . htmlspecialchars($row['username']) . '</td>';
            echo '<td>' . htmlspecialchars($row['email']) . '</td>';
            echo '</tr>';
        }
        echo '</table>';
    } else {
        echo '<p>No results found.</p>';
    }
} else {
    echo '<p style="color:red">Error: ' . htmlspecialchars($conn->error) . '</p>';
}

$conn->close();
?>
