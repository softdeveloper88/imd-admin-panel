-- iMD App Schema Migration v2
-- Adds: download tracking, subscriptions, package visibility, trending, tab content, admin logs, analytics

USE imd_app;

-- ─── User status field ───
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_active TINYINT(1) DEFAULT 1 AFTER subscription_expires,
  ADD COLUMN IF NOT EXISTS email VARCHAR(255) DEFAULT NULL AFTER username;

-- ─── Subscription plans ───
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

-- ─── Download tracking (per user) ───
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

-- ─── Package visibility / access control per subscription tier ───
CREATE TABLE IF NOT EXISTS package_access (
  id INT AUTO_INCREMENT PRIMARY KEY,
  package_name VARCHAR(255) NOT NULL,
  min_access_level INT DEFAULT 1 COMMENT 'Minimum subscription level needed',
  is_visible TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_pkg (package_name)
) ENGINE=InnoDB;

-- ─── Tab content control (admin manages what shows in each tab) ───
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

-- ─── Package categories ───
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

-- ─── Package-to-category mapping ───
CREATE TABLE IF NOT EXISTS package_categories (
  id INT AUTO_INCREMENT PRIMARY KEY,
  package_name VARCHAR(255) NOT NULL,
  category_id INT NOT NULL,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
  UNIQUE KEY unique_pkg_cat (package_name, category_id)
) ENGINE=InnoDB;

-- ─── Admin action log ───
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

-- ─── Analytics: download counts (global, for trending) ───
CREATE TABLE IF NOT EXISTS download_stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  package_name VARCHAR(255) NOT NULL,
  download_count INT DEFAULT 0,
  last_downloaded TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_pkg (package_name)
) ENGINE=InnoDB;
