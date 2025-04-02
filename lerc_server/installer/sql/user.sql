DROP USER IF EXISTS 'lerc_user'@'localhost';
FLUSH PRIVILEGES;
CREATE USER 'lerc_user'@'localhost' IDENTIFIED BY 'LERC_DB_USER_PASSWORD';
GRANT ALL PRIVILEGES ON lerc . * TO 'lerc_user'@'localhost';
FLUSH PRIVILEGES;

