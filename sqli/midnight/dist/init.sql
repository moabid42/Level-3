CREATE DATABASE IF NOT EXISTS challenge_db;
USE challenge_db;
CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50),
  password VARCHAR(50)
);
INSERT INTO users (username, password) VALUES ('admin', 'SuperSecretPassword'); 