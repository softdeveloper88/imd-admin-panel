-- Migration v6: Token-Based Access Control
-- Run this migration after all previous migrations (v1-v5)

-- ─── Tokens table ───
CREATE TABLE IF NOT EXISTS tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  token_code VARCHAR(36) NOT NULL UNIQUE,
  token_type ENUM('single', 'reseller_bundle', 'reseller_unit') NOT NULL DEFAULT 'single',
  parent_bundle_id INT DEFAULT NULL,
  duration_type ENUM('monthly', 'yearly', 'custom') NOT NULL DEFAULT 'monthly',
  duration_days INT NOT NULL DEFAULT 30,
  status ENUM('available', 'active', 'expired', 'revoked') NOT NULL DEFAULT 'available',
  assigned_to_user INT DEFAULT NULL,
  assigned_to_reseller VARCHAR(255) DEFAULT NULL,
  used_at TIMESTAMP NULL DEFAULT NULL,
  expires_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Token code validity cutoff (not subscription expiry)',
  created_by VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (parent_bundle_id) REFERENCES tokens(id) ON DELETE SET NULL,
  FOREIGN KEY (assigned_to_user) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_token_code (token_code),
  INDEX idx_status (status),
  INDEX idx_parent_bundle (parent_bundle_id),
  INDEX idx_reseller (assigned_to_reseller),
  INDEX idx_expires (expires_at)
) ENGINE=InnoDB;

-- ─── Token history table ───
CREATE TABLE IF NOT EXISTS token_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  token_id INT NOT NULL,
  user_id INT NOT NULL,
  action ENUM('register', 'extend') NOT NULL,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  valid_from TIMESTAMP NOT NULL,
  valid_until TIMESTAMP NOT NULL,
  FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_token (token_id),
  INDEX idx_user (user_id)
) ENGINE=InnoDB;

-- ─── Extend users table for token-based access ───
ALTER TABLE users
  ADD COLUMN active_token_id INT DEFAULT NULL AFTER stripe_customer_id,
  ADD COLUMN valid_until TIMESTAMP NULL DEFAULT NULL AFTER active_token_id,
  ADD COLUMN account_status ENUM('active', 'suspended', 'expired') DEFAULT 'active' AFTER valid_until;

ALTER TABLE users
  ADD CONSTRAINT fk_users_active_token FOREIGN KEY (active_token_id) REFERENCES tokens(id) ON DELETE SET NULL;

ALTER TABLE users
  ADD INDEX idx_valid_until (valid_until),
  ADD INDEX idx_account_status (account_status);
