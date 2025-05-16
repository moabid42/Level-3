<?php
$output = '';
$error = '';

$blacklist = [
    'rm', 'mv', 'cp', 'dd', 'cat', 'less', 'more', 'head', 'tail', 'vi', 'vim', 'nano',
    'nc', 'netcat', 'wget', 'curl', 'ssh', 'scp', 'sftp', 'telnet', 'ftp',
    'python', 'perl', 'ruby', 'php', 'node', 'bash', 'sh', 'zsh', 'ksh', 'nl',
    'su', 'sudo', 'strings', 'chmod', 'chown', 'chgrp', 'passwd', 'useradd', 'userdel',
    'iptables', 'ufw', 'firewall-cmd', 'systemctl', 'service',
    'kill', 'killall', 'pkill', 'ps', 'top', 'htop',
    'ifconfig', 'ip', 'route', 'arp', 'netstat',
    'find', 'grep', 'awk', 'sed', 'xargs',
    'tar', 'gzip', 'bzip2', 'zip', 'unzip',
    'mount', 'umount', 'fdisk', 'mkfs', 'fsck',
    'crontab', 'at', 'batch',
    'export', 'set', 'unset', 'env',
    '>', '<', '|', '&', ';', '`', '(', ')', '$', '[', ']'
];

function isValidInput($input)
{
    $input = strtolower($input);
    $lettersOnly = preg_replace('/[^a-z]/', '', $input);
    return preg_match('/^[fiberglass]*$/', $lettersOnly);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['command'])) {
    $command = $_POST['command'];
    $command = trim($command);
    $command = preg_replace('/\s+/', ' ', $command);
    
    if (!isValidInput($command)) {
        $error = "Error: Input can only contain letters from 'fiberglass' and spaces.";
    } else {
        $commandLower = strtolower($command);
        foreach ($blacklist as $restricted) {
            if (strpos($commandLower, $restricted) !== false) {
                $error = "Error: Command contains restricted keyword: $restricted";
                break;
            }
        }
        
        if (empty($error)) {
            $output = shell_exec('bash -c "' . escapeshellcmd($command) . '" 2>&1');
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Bash Command Executor</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 h2{
            color: #333;
            text-align: center;
        }
        .command-form {
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        pre {
            background-color: #f8f8f8;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .error {
            color: #ff0000;
            background-color: #ffeeee;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        .hint {
            color: #666;
            font-size: 0.9em;
            margin-top: 20px;
            padding: 10px;
            background-color: #f0f0f0;
            border-radius: 4px;
        }
        .restrictions {
            color: #666;
            font-size: 0.8em;
            margin-top: 20px;
            padding: 10px;
            background-color: #f0f0f0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Bash Command Executor</h1>
        <h2>This challenge is fiberglass secure, can you break it ?</h2>
        <form method="POST" class="command-form">
            <input type="text" name="command" placeholder="Enter your command here..." required>
            <button type="submit">Execute</button>
        </form>
        
        <?php if (!empty($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($output !== ''): ?>
            <h2>Output:</h2>
            <pre><?php echo htmlspecialchars($output); ?></pre>
        <?php endif; ?>
    </div>
</body>
</html>
