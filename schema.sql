-- iMD App MySQL Schema
-- Run this script to initialize the user authentication database.

CREATE DATABASE IF NOT EXISTS imd_app
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE imd_app;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password_salt VARCHAR(64) NOT NULL,
  password_hash VARCHAR(128) NOT NULL,
  subscription_type VARCHAR(50) DEFAULT 'free',
  subscription_expires DATE DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token VARCHAR(128) NOT NULL UNIQUE,
  device_id VARCHAR(255) DEFAULT NULL,
  is_active TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_token (token),
  INDEX idx_user_active (user_id, is_active)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS favorites (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_package (user_id, package_name)
) ENGINE=InnoDB;

-- Seed a test user (password: test123)
-- Salt and hash generated via Node.js crypto.pbkdf2Sync with 120000 iterations, sha256, 32 bytes
INSERT INTO users (username, password_salt, password_hash, subscription_type, subscription_expires)
VALUES ('testuser', 'e566e9d4e7834bcfb8bcb5ad7fd3df55', '02d2299c13240a17535b3f4bc1a96fed65df107c2924cedaae7dd5ff3180cd30', 'premium', '2027-12-31')
ON DUPLICATE KEY UPDATE username=username;

-- To generate another user, run:
--   node -e "const c=require('crypto');const s=c.randomBytes(16).toString('hex');console.log(s,c.pbkdf2Sync('YOUR_PASSWORD',s,120000,32,'sha256').toString('hex'))"
