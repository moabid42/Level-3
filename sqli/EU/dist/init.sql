CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50),
  email VARCHAR(100)
);

CREATE TABLE admin (
  id INT AUTO_INCREMENT PRIMARY KEY,
  secret VARCHAR(255)
);

INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com'), ('bob', 'bob@example.com');
INSERT INTO admin (secret) VALUES ('flag{this_is_the_secret}'); 