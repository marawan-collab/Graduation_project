-- Add private_key and public_key columns to users table
ALTER TABLE users
ADD COLUMN private_key TEXT,
ADD COLUMN public_key TEXT;
 
-- Update documents table to include signature_time and signed_by
ALTER TABLE documents
ADD COLUMN signature_time TIMESTAMP NULL,
ADD COLUMN signed_by INT,
ADD FOREIGN KEY (signed_by) REFERENCES users(id) ON DELETE SET NULL; 