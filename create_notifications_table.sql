-- =====================================================
-- Notifications Table for Patient-Doctor Communication
-- =====================================================

CREATE TABLE IF NOT EXISTS `notifications` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `patient_id` int(11) NOT NULL,
  `doctor_id` int(11) DEFAULT NULL COMMENT 'Doctor who triggered the notification',
  `notification_type` enum('doctor_access','appointment','prescription','medical_record','message') NOT NULL DEFAULT 'doctor_access',
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `related_resource_type` varchar(50) DEFAULT NULL COMMENT 'Type: medical_record, appointment, prescription, etc.',
  `related_resource_id` int(11) DEFAULT NULL COMMENT 'ID of the related resource',
  `is_read` tinyint(1) DEFAULT 0 COMMENT '0=unread, 1=read',
  `read_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_notifications_patient` (`patient_id`),
  KEY `idx_notifications_doctor` (`doctor_id`),
  KEY `idx_notifications_read` (`patient_id`, `is_read`),
  KEY `idx_notifications_created` (`created_at`),
  FOREIGN KEY (`patient_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`doctor_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- =====================================================
-- Index for performance
-- =====================================================

CREATE INDEX IF NOT EXISTS `idx_notifications_unread` ON `notifications`(`patient_id`, `is_read`, `created_at`);

