-- =====================================================
-- Migration Script: Update Patient Database Schema
-- Run this on your existing database to add new fields
-- =====================================================

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";

-- =====================================================
-- Update existing tables with new columns
-- =====================================================

-- Update medical_records table
ALTER TABLE `medical_records` 
    ADD COLUMN IF NOT EXISTS `signature` longblob DEFAULT NULL COMMENT 'Digital signature of the record',
    ADD COLUMN IF NOT EXISTS `signature_hash` varchar(255) DEFAULT NULL COMMENT 'Hash of signature for verification';

-- Update radiology_files table (if it exists)
-- Add new columns for enhanced MRI tracking
ALTER TABLE `radiology_files`
    ADD COLUMN IF NOT EXISTS `analysis_model_version` varchar(50) DEFAULT NULL COMMENT 'Model version used for analysis',
    ADD COLUMN IF NOT EXISTS `file_size` bigint(20) DEFAULT NULL COMMENT 'File size in bytes';

-- Ensure folder column exists (may already exist from dynamic creation)
ALTER TABLE `radiology_files`
    ADD COLUMN IF NOT EXISTS `folder` varchar(255) DEFAULT NULL COMMENT 'Folder name for organizing scans';

-- Update users table - ensure all patient fields exist
ALTER TABLE `users`
    ADD COLUMN IF NOT EXISTS `profile_photo` longblob DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `first_name` varchar(50) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `last_name` varchar(50) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `phone` varchar(20) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `date_of_birth` date DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `gender` enum('M','F','O') DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `blood_type` varchar(5) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `emergency_contact` varchar(100) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS `emergency_phone` varchar(20) DEFAULT NULL;

-- =====================================================
-- Create new optional enhancement tables
-- =====================================================

-- Patient Vital Signs Table
CREATE TABLE IF NOT EXISTS `patient_vital_signs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `patient_id` int(11) NOT NULL,
  `recorded_date` datetime NOT NULL,
  `recorded_by` int(11) DEFAULT NULL COMMENT 'User ID who recorded (doctor/nurse)',
  `blood_pressure_systolic` int(11) DEFAULT NULL,
  `blood_pressure_diastolic` int(11) DEFAULT NULL,
  `heart_rate` int(11) DEFAULT NULL,
  `temperature` decimal(4,1) DEFAULT NULL COMMENT 'Temperature in Celsius',
  `weight` decimal(5,2) DEFAULT NULL COMMENT 'Weight in kg',
  `height` decimal(5,2) DEFAULT NULL COMMENT 'Height in cm',
  `oxygen_saturation` decimal(4,1) DEFAULT NULL COMMENT 'O2 saturation percentage',
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_vitals_patient` (`patient_id`),
  KEY `idx_vitals_date` (`recorded_date`),
  FOREIGN KEY (`patient_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`recorded_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Patient Allergies Table
CREATE TABLE IF NOT EXISTS `patient_allergies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `patient_id` int(11) NOT NULL,
  `allergen` varchar(100) NOT NULL COMMENT 'Substance causing allergy',
  `reaction` text DEFAULT NULL COMMENT 'Type of reaction',
  `severity` enum('mild','moderate','severe','life_threatening') DEFAULT 'moderate',
  `diagnosed_date` date DEFAULT NULL,
  `diagnosed_by` int(11) DEFAULT NULL COMMENT 'Doctor ID who diagnosed',
  `notes` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1 COMMENT '1 if allergy is still active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_allergies_patient` (`patient_id`),
  KEY `idx_allergies_active` (`patient_id`, `is_active`),
  FOREIGN KEY (`patient_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`diagnosed_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Patient Lab Results Table
CREATE TABLE IF NOT EXISTS `patient_lab_results` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `patient_id` int(11) NOT NULL,
  `test_name` varchar(255) NOT NULL,
  `test_type` varchar(100) DEFAULT NULL COMMENT 'Blood, Urine, Imaging, etc.',
  `test_date` datetime NOT NULL,
  `ordered_by` int(11) DEFAULT NULL COMMENT 'Doctor ID who ordered',
  `results` text DEFAULT NULL COMMENT 'Test results data (can be JSON or text)',
  `normal_range` varchar(100) DEFAULT NULL,
  `status` enum('pending','completed','cancelled') DEFAULT 'pending',
  `file_attachment` varchar(255) DEFAULT NULL COMMENT 'Path to attached file if any',
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_lab_patient` (`patient_id`),
  KEY `idx_lab_date` (`test_date`),
  KEY `idx_lab_status` (`status`),
  FOREIGN KEY (`patient_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`ordered_by`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Medical Record MRI Links Table
CREATE TABLE IF NOT EXISTS `medical_record_mri_links` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `medical_record_id` int(11) NOT NULL,
  `radiology_file_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_record_file_link` (`medical_record_id`, `radiology_file_id`),
  KEY `idx_link_record` (`medical_record_id`),
  KEY `idx_link_file` (`radiology_file_id`),
  FOREIGN KEY (`medical_record_id`) REFERENCES `medical_records`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`radiology_file_id`) REFERENCES `radiology_files`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================
-- Add indexes for performance
-- =====================================================

-- Add indexes if they don't exist (MySQL doesn't support IF NOT EXISTS for indexes)
-- You may need to check and drop manually if they exist

-- Composite indexes
CREATE INDEX IF NOT EXISTS `idx_patient_dob` ON `users`(`date_of_birth`);
CREATE INDEX IF NOT EXISTS `idx_medical_record_patient_date` ON `medical_records`(`patient_id`, `record_date`);
CREATE INDEX IF NOT EXISTS `idx_radiology_tumor_confidence` ON `radiology_files`(`tumor_detected`, `confidence`);
CREATE INDEX IF NOT EXISTS `idx_appointment_patient_status` ON `appointments`(`patient_id`, `status`);
CREATE INDEX IF NOT EXISTS `idx_prescription_patient_status` ON `prescriptions`(`patient_id`, `status`);

-- =====================================================
-- Create views for easier querying
-- =====================================================

-- View: Patient Complete Profile
CREATE OR REPLACE VIEW `patient_complete_profile` AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.first_name,
    u.last_name,
    CONCAT(u.first_name, ' ', u.last_name) AS full_name,
    u.phone,
    u.date_of_birth,
    TIMESTAMPDIFF(YEAR, u.date_of_birth, CURDATE()) AS age,
    u.gender,
    u.blood_type,
    u.emergency_contact,
    u.emergency_phone,
    u.created_at AS registration_date,
    (SELECT COUNT(*) FROM appointments WHERE patient_id = u.id) AS total_appointments,
    (SELECT COUNT(*) FROM medical_records WHERE patient_id = u.id) AS total_medical_records,
    (SELECT COUNT(*) FROM prescriptions WHERE patient_id = u.id AND status = 'active') AS active_prescriptions,
    (SELECT COUNT(*) FROM radiology_files WHERE patient_id = u.id) AS total_scans,
    (SELECT COUNT(*) FROM radiology_files WHERE patient_id = u.id AND tumor_detected IS NOT NULL AND tumor_detected != 'No Tumor' AND tumor_detected != 'notumor') AS scans_with_tumors
FROM users u
WHERE u.role = 'patient';

-- View: Patient MRI Analysis Summary
CREATE OR REPLACE VIEW `patient_mri_summary` AS
SELECT 
    rf.patient_id,
    COUNT(*) AS total_scans,
    SUM(CASE WHEN rf.tumor_detected IS NOT NULL THEN 1 ELSE 0 END) AS analyzed_scans,
    SUM(CASE WHEN rf.tumor_detected IS NOT NULL AND rf.tumor_detected != 'No Tumor' AND rf.tumor_detected != 'notumor' THEN 1 ELSE 0 END) AS tumor_detected_count,
    MAX(rf.confidence) AS highest_confidence,
    MIN(rf.confidence) AS lowest_confidence,
    AVG(rf.confidence) AS average_confidence,
    MAX(rf.analysis_date) AS latest_analysis_date
FROM radiology_files rf
GROUP BY rf.patient_id;

-- =====================================================
-- COMMIT Changes
-- =====================================================
COMMIT;

-- =====================================================
-- Migration Complete
-- =====================================================

