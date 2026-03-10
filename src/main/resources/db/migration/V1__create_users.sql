CREATE TABLE users (
id VARCHAR(36) NOT NULL,
email VARCHAR(255) NOT NULL,
password_hash VARCHAR(255) NOT NULL,
role ENUM('USER', 'ADMIN') NOT NULL DEFAULT 'USER',
trust_score INT NOT NULL DEFAULT 50,
token_version INT NOT NULL DEFAULT 0,
account_locked BOOLEAN NOT NULL DEFAULT FALSE,
failed_login_attempts INT NOT NULL DEFAULT 0,
last_active_at DATETIME NULL,
created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
version    BIGINT NOT NULL DEFAULT 0,

CONSTRAINT pk_users PRIMARY KEY (id),
CONSTRAINT uq_users_email UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_users_last_active_at ON users(last_active_at);
CREATE INDEX idx_users_trust_score ON users(trust_score);
-- seed first admin user
-- password is : Admin@Zoick123(bcrypt hashed)
-- change this passsword immediately project enters real enivornment
INSERT INTO users (
    id,
    email,
    password_hash,
    role,
    trust_score,
    token_version,
    account_locked,
    failed_login_attempts,
    created_at,
    updated_at
) VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'admin@zoick.com',
    '$2a$12$Fy7DW3m74NZPRYCzWGUzQeZKRoDq9TpEzZy8AxZ6oc7afu2xkOM9O',
    'ADMIN',
    100,
    0,
    FALSE,
    0,
    NOW(),
    NOW()
);