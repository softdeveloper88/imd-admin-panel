-- iMD App Migration v3 — Subscriptions, Payments, Notifications
-- Run this AFTER migration_full.sql has been applied.

-- ─── New columns on users ───
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255) DEFAULT NULL AFTER email;
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255) DEFAULT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auto_renew TINYINT(1) DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status ENUM('active','past_due','cancelled','expired') DEFAULT 'active';

-- ─── New columns on subscription_plans ───
ALTER TABLE subscription_plans ADD COLUMN IF NOT EXISTS stripe_price_id VARCHAR(255) DEFAULT NULL;
ALTER TABLE subscription_plans ADD COLUMN IF NOT EXISTS features JSON DEFAULT NULL;

-- ─── Payments table ───
CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  stripe_payment_id VARCHAR(255) DEFAULT NULL,
  stripe_subscription_id VARCHAR(255) DEFAULT NULL,
  plan_id INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  currency VARCHAR(3) DEFAULT 'USD',
  status ENUM('pending','completed','failed','refunded') DEFAULT 'pending',
  payment_method VARCHAR(50) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (plan_id) REFERENCES subscription_plans(id),
  INDEX idx_user (user_id),
  INDEX idx_stripe_payment (stripe_payment_id),
  INDEX idx_stripe_sub (stripe_subscription_id)
) ENGINE=InnoDB;

-- ─── Payment event logs ───
CREATE TABLE IF NOT EXISTS payment_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(100) NOT NULL,
  stripe_event_id VARCHAR(255) DEFAULT NULL,
  user_id INT DEFAULT NULL,
  data JSON DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_event_type (event_type),
  INDEX idx_user (user_id)
) ENGINE=InnoDB;

-- ─── Admin notifications ───
CREATE TABLE IF NOT EXISTS admin_notifications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  type VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  message TEXT DEFAULT NULL,
  data JSON DEFAULT NULL,
  is_read TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_unread (is_read, created_at)
) ENGINE=InnoDB;

-- ─── Password reset tokens ───
CREATE TABLE IF NOT EXISTS password_resets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_token (token)
) ENGINE=InnoDB;

-- ─── App settings (key-value) ───
CREATE TABLE IF NOT EXISTS app_settings (
  setting_key VARCHAR(100) PRIMARY KEY,
  setting_value TEXT DEFAULT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ─── FCM token on sessions ───
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS fcm_token VARCHAR(255) DEFAULT NULL;

-- ─── Seed default app settings ───
INSERT IGNORE INTO app_settings (setting_key, setting_value) VALUES
  ('maintenance_mode', 'false'),
  ('min_app_version', '1.0.0'),
  ('force_update', 'false'),
  ('site_name', 'iMedicalDoctor'),
  ('contact_email', 'support@imd.com');

-- ─── Update existing subscription_plans with features ───
UPDATE subscription_plans SET features = '["Access to free content","Limited question banks"]' WHERE name = 'Free' AND features IS NULL;
UPDATE subscription_plans SET features = '["Full question bank access","Reference materials","Monthly updates"]' WHERE name = 'Monthly' AND features IS NULL;
UPDATE subscription_plans SET features = '["Full question bank access","Reference materials","Clinical guides","Priority support","Save 33% vs monthly"]' WHERE name = 'Yearly' AND features IS NULL;
UPDATE subscription_plans SET features = '["Lifetime full access","All content included","All future updates","Priority support"]' WHERE name = 'Lifetime' AND features IS NULL;
