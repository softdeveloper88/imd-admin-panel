-- Migration v7: Token recipient metadata
-- Adds recipient tracking fields for admin-generated tokens.

ALTER TABLE tokens
  ADD COLUMN recipient_name VARCHAR(255) NULL AFTER assigned_to_reseller,
  ADD COLUMN recipient_email VARCHAR(255) NULL AFTER recipient_name;
