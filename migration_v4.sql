-- iMD App Schema Migration v4
-- Adds: test_history, question_favorites, backups

USE imd_app;

-- ─── Test history (one row per completed test) ───
CREATE TABLE IF NOT EXISTS test_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  score DECIMAL(5,2) NOT NULL DEFAULT 0.00,
  correct INT NOT NULL DEFAULT 0,
  wrong INT NOT NULL DEFAULT 0,
  unanswered INT NOT NULL DEFAULT 0,
  total INT NOT NULL DEFAULT 0,
  mode VARCHAR(50) DEFAULT 'Reading',
  question_ids JSON DEFAULT NULL,
  answers JSON DEFAULT NULL COMMENT '{"questionId": selectedAnswerId, ...}',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_pkg (user_id, package_name),
  INDEX idx_created (created_at)
) ENGINE=InnoDB;

-- ─── Per-question favorites ───
CREATE TABLE IF NOT EXISTS question_favorites (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  question_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_user_pkg_q (user_id, package_name, question_id),
  INDEX idx_user_pkg (user_id, package_name)
) ENGINE=InnoDB;

-- ─── Backups (test history + favorites snapshot with short code) ───
CREATE TABLE IF NOT EXISTS backups (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  backup_code VARCHAR(10) NOT NULL UNIQUE,
  data JSON NOT NULL COMMENT 'Snapshot of test_history + question_favorites',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_pkg (user_id, package_name),
  INDEX idx_code (backup_code)
) ENGINE=InnoDB;
