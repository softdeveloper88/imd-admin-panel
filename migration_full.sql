-- iMD App Full Schema (Production)
-- Run this on your production MySQL database to set up everything.
-- Import via phpMyAdmin or mysql CLI.

-- NOTE: On Hostinger, the database is already created for you.
-- Remove or comment out the next two lines if using phpMyAdmin import:
-- CREATE DATABASE IF NOT EXISTS imd_app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE imd_app;

-- ─── Base tables ───

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

-- ─── v2 additions ───

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_active TINYINT(1) DEFAULT 1 AFTER subscription_expires,
  ADD COLUMN IF NOT EXISTS email VARCHAR(255) DEFAULT NULL AFTER username;

CREATE TABLE IF NOT EXISTS subscription_plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description TEXT DEFAULT NULL,
  duration_days INT NOT NULL DEFAULT 30,
  price DECIMAL(10,2) DEFAULT 0.00,
  access_level INT DEFAULT 1 COMMENT '1=basic, 2=standard, 3=premium, 4=enterprise',
  is_active TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT IGNORE INTO subscription_plans (name, description, duration_days, price, access_level) VALUES
  ('Free', 'Basic free access', 0, 0.00, 1),
  ('Monthly', '30-day premium access', 30, 9.99, 3),
  ('Yearly', '365-day premium access', 365, 79.99, 3),
  ('Lifetime', 'Permanent premium access', 36500, 199.99, 4);

CREATE TABLE IF NOT EXISTS user_downloads (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  file_size BIGINT DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_download (user_id, package_name),
  INDEX idx_package (package_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS package_access (
  id INT AUTO_INCREMENT PRIMARY KEY,
  package_name VARCHAR(255) NOT NULL,
  min_access_level INT DEFAULT 1 COMMENT 'Minimum subscription level needed',
  is_visible TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_pkg (package_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tab_content (
  id INT AUTO_INCREMENT PRIMARY KEY,
  tab_name VARCHAR(50) NOT NULL COMMENT 'newest, popular, trending, updates, paid',
  package_name VARCHAR(255) NOT NULL,
  sort_order INT DEFAULT 0,
  is_pinned TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_tab_pkg (tab_name, package_name),
  INDEX idx_tab (tab_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS categories (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  sort_order INT DEFAULT 0,
  is_active TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

INSERT IGNORE INTO categories (name, sort_order) VALUES
  ('Amedex', 1), ('NBME', 2), ('OVID Books', 3), ('Access Medicine', 4),
  ('Sanford', 5), ('Elsevier Videos', 6), ('Elsevier Inc', 7), ('PassMedicine', 8);

CREATE TABLE IF NOT EXISTS package_categories (
  id INT AUTO_INCREMENT PRIMARY KEY,
  package_name VARCHAR(255) NOT NULL,
  category_id INT NOT NULL,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
  UNIQUE KEY unique_pkg_cat (package_name, category_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS admin_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  admin_username VARCHAR(255) NOT NULL,
  action VARCHAR(100) NOT NULL,
  target_type VARCHAR(50) DEFAULT NULL COMMENT 'user, package, subscription, tab, category',
  target_id VARCHAR(255) DEFAULT NULL,
  details TEXT DEFAULT NULL,
  ip_address VARCHAR(45) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS download_stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  package_name VARCHAR(255) NOT NULL,
  download_count INT DEFAULT 0,
  last_downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_pkg_stat (package_name)
) ENGINE=InnoDB;
