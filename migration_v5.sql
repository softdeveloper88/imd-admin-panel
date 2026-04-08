-- iMD App Schema Migration v5
-- Adds: subject_label, system_label, total_time_secs, question_times, done to test_history

ALTER TABLE test_history
  ADD COLUMN subject_label VARCHAR(500) DEFAULT NULL AFTER answers,
  ADD COLUMN system_label VARCHAR(500) DEFAULT NULL AFTER subject_label,
  ADD COLUMN total_time_secs INT NOT NULL DEFAULT 0 AFTER system_label,
  ADD COLUMN question_times JSON DEFAULT NULL AFTER total_time_secs,
  ADD COLUMN done TINYINT(1) NOT NULL DEFAULT 1 AFTER question_times;
