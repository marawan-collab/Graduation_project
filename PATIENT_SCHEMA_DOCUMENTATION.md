# Patient Database Schema Documentation

## Overview
This document describes the complete database schema for the patient management system, including all tables related to patient data, medical records, MRI analysis, appointments, and prescriptions.

---

## Core Tables

### 1. `users` Table
**Purpose**: Stores all user accounts including patients, doctors, and admins.

#### Key Fields for Patients:
- **Basic Info**: `first_name`, `last_name`, `username`, `email`, `phone`
- **Demographics**: `date_of_birth`, `gender` (M/F/O), `blood_type`
- **Emergency Contacts**: `emergency_contact`, `emergency_phone`
- **Authentication**: `password`, `2fa_secret`, `auth0_id`
- **Profile**: `profile_photo` (BLOB)
- **Role-based**: `role` (patient/doctor/admin)

#### Relationships:
- Referenced by: `medical_records`, `appointments`, `prescriptions`, `radiology_files`, `doctor_patient_assignments`

---

### 2. `medical_records` Table
**Purpose**: Stores medical records created by doctors for patients.

#### Fields:
- `id` - Primary key
- `patient_id` - Foreign key to `users.id`
- `doctor_id` - Foreign key to `users.id`
- `record_date` - Date/time of the medical record
- `diagnosis` - Diagnosis text
- `treatment` - Treatment plan
- `notes` - Additional notes
- `follow_up_date` - Recommended follow-up date
- `signature` - Digital signature (BLOB)
- `signature_hash` - Hash for signature verification
- `created_at`, `updated_at` - Timestamps

#### Usage:
- Doctors create medical records during or after appointments
- Can be digitally signed using RSA keys
- Linked to MRI scans via `medical_record_mri_links` table

---

### 3. `radiology_files` Table
**Purpose**: Stores radiology/MRI scan files with AI analysis results.

#### Fields:
- `id` - Primary key
- `patient_id` - Foreign key to `users.id`
- `original_filename` - Original uploaded filename
- `stored_filename` - Server-stored filename
- `file_type` - File extension (jpg, png, pdf, etc.)
- `folder` - Folder name for organizing scans
- **MRI Analysis Fields**:
  - `tumor_detected` - Result: "Glioma", "Meningioma", "Pituitary", "No Tumor", etc.
  - `confidence` - Confidence score (0.000 to 1.000)
  - `analysis_date` - When analysis was performed
  - `analysis_model_version` - Model version used
- `file_size` - File size in bytes
- `uploaded_at`, `created_at`, `updated_at` - Timestamps

#### MRI Analysis Results:
Based on `mri_analysis.py`:
- Possible tumor types: **Glioma**, **Meningioma**, **Pituitary**, **No Tumor**
- Confidence scores range from 0.000 to 1.000
- Analysis is automatically performed on image uploads

#### Usage:
- Patients upload MRI/radiology scans through the web interface
- Images are automatically analyzed using TensorFlow/Keras model
- Results are stored in this table
- Scans can be organized into folders

---

### 4. `appointments` Table
**Purpose**: Manages patient appointments with doctors.

#### Fields:
- `id` - Primary key
- `patient_id` - Foreign key to `users.id`
- `doctor_id` - Foreign key to `users.id`
- `appointment_date` - Scheduled date/time
- `status` - Enum: 'scheduled', 'completed', 'cancelled', 'no_show'
- `reason` - Reason for appointment
- `notes` - Additional notes
- `created_at`, `updated_at` - Timestamps

#### Workflow:
1. Patient schedules appointment
2. Automatically creates `doctor_patient_assignments` entry
3. Doctor can update status and add notes
4. After completion, doctor can create medical records

---

### 5. `prescriptions` Table
**Purpose**: Stores medications prescribed by doctors to patients.

#### Fields:
- `id` - Primary key
- `patient_id` - Foreign key to `users.id`
- `doctor_id` - Foreign key to `users.id`
- `prescription_date` - Date prescribed
- `medication_name` - Name of medication
- `dosage` - Dosage amount
- `frequency` - Frequency (e.g., "twice daily")
- `duration` - Duration (e.g., "30 days")
- `instructions` - Additional instructions
- `status` - Enum: 'active', 'completed', 'cancelled'
- `created_at`, `updated_at` - Timestamps

---

### 6. `doctor_patient_assignments` Table
**Purpose**: Tracks which doctors are assigned to which patients.

#### Fields:
- `id` - Primary key
- `doctor_id` - Foreign key to `users.id`
- `patient_id` - Foreign key to `users.id`
- `assigned_date` - When assignment was made
- `status` - Enum: 'active', 'inactive'
- `notes` - Notes about the assignment

#### Usage:
- Automatically created when patient schedules appointment with doctor
- Used to filter which patients a doctor can see/manage

---

## Optional Enhancement Tables

### 7. `patient_vital_signs` Table
**Purpose**: Track patient vital signs over time.

#### Fields:
- Blood pressure (systolic/diastolic)
- Heart rate
- Temperature
- Weight, Height
- Oxygen saturation
- Recorded by (doctor/nurse)
- Notes

---

### 8. `patient_allergies` Table
**Purpose**: Store patient allergies and reactions.

#### Fields:
- `allergen` - Substance causing allergy
- `reaction` - Type of reaction
- `severity` - mild/moderate/severe/life_threatening
- `diagnosed_date` - When diagnosed
- `diagnosed_by` - Doctor ID
- `is_active` - Whether allergy is still active

---

### 9. `patient_lab_results` Table
**Purpose**: Store lab test results.

#### Fields:
- `test_name` - Name of test
- `test_type` - Blood, Urine, Imaging, etc.
- `test_date` - When test was performed
- `ordered_by` - Doctor ID
- `results` - Test results (text or JSON)
- `normal_range` - Normal value range
- `status` - pending/completed/cancelled
- `file_attachment` - Path to attached file

---

### 10. `medical_record_mri_links` Table
**Purpose**: Links medical records to specific MRI scans.

#### Fields:
- `medical_record_id` - Foreign key to `medical_records.id`
- `radiology_file_id` - Foreign key to `radiology_files.id`

#### Usage:
- Allows doctors to reference specific MRI scans in medical records
- Creates a relationship between diagnosis and supporting imaging

---

## Database Views

### `patient_complete_profile` View
**Purpose**: Provides a comprehensive patient profile with aggregated statistics.

#### Returns:
- Patient basic information
- Calculated age from date of birth
- Count of appointments
- Count of medical records
- Count of active prescriptions
- Count of total scans
- Count of scans with detected tumors

**Example Query:**
```sql
SELECT * FROM patient_complete_profile WHERE id = 123;
```

---

### `patient_mri_summary` View
**Purpose**: Aggregates MRI analysis data per patient.

#### Returns:
- Total number of scans
- Number of analyzed scans
- Number of scans with tumors detected
- Highest, lowest, and average confidence scores
- Latest analysis date

**Example Query:**
```sql
SELECT * FROM patient_mri_summary WHERE patient_id = 123;
```

---

## Common Queries

### Get Patient with All Related Data
```sql
SELECT 
    u.*,
    (SELECT COUNT(*) FROM appointments WHERE patient_id = u.id) as appointment_count,
    (SELECT COUNT(*) FROM medical_records WHERE patient_id = u.id) as record_count,
    (SELECT COUNT(*) FROM radiology_files WHERE patient_id = u.id) as scan_count
FROM users u
WHERE u.id = ? AND u.role = 'patient';
```

### Get All MRI Scans with Analysis Results
```sql
SELECT 
    rf.*,
    u.first_name,
    u.last_name
FROM radiology_files rf
JOIN users u ON rf.patient_id = u.id
WHERE rf.patient_id = ?
ORDER BY rf.analysis_date DESC;
```

### Get Patient Medical History with MRI Links
```sql
SELECT 
    mr.*,
    GROUP_CONCAT(rf.original_filename) as linked_scans
FROM medical_records mr
LEFT JOIN medical_record_mri_links mrml ON mr.id = mrml.medical_record_id
LEFT JOIN radiology_files rf ON mrml.radiology_file_id = rf.id
WHERE mr.patient_id = ?
GROUP BY mr.id
ORDER BY mr.record_date DESC;
```

### Get Patients with Tumor Detections
```sql
SELECT 
    u.id,
    u.first_name,
    u.last_name,
    rf.tumor_detected,
    rf.confidence,
    rf.analysis_date
FROM users u
JOIN radiology_files rf ON u.id = rf.patient_id
WHERE rf.tumor_detected IS NOT NULL 
  AND rf.tumor_detected != 'No Tumor' 
  AND rf.tumor_detected != 'notumor'
ORDER BY rf.analysis_date DESC;
```

---

## MRI Analysis Integration

The system uses TensorFlow/Keras for brain tumor detection in MRI images:

### Model Location:
- Environment variable: `MRI_MODEL_PATH`
- Default: `INFO/model/mri_brain_tumor.h5`

### Analysis Process:
1. Patient uploads image file
2. System detects image type (jpg, png, etc.)
3. `analyze_mri_image()` function is called from `mri_analysis.py`
4. Results stored in `radiology_files` table:
   - `tumor_detected`: Classification result
   - `confidence`: Model confidence (0.000-1.000)
   - `analysis_date`: Timestamp

### Possible Results:
- **Glioma** - Type of brain tumor
- **Meningioma** - Type of brain tumor
- **Pituitary** - Pituitary tumor
- **No Tumor** / **notumor** - No tumor detected

---

## Data Relationships Diagram

```
users (patients)
├── medical_records
│   └── medical_record_mri_links → radiology_files
├── appointments
├── prescriptions
├── radiology_files
├── doctor_patient_assignments → users (doctors)
├── patient_vital_signs (optional)
├── patient_allergies (optional)
└── patient_lab_results (optional)
```

---

## Security Considerations

1. **Patient Data Privacy**: All tables include foreign key constraints to ensure data integrity
2. **Digital Signatures**: Medical records can be signed using RSA keys stored in `users.private_key` and `users.public_key`
3. **Cascade Deletes**: When a patient is deleted, all related records are automatically removed
4. **Access Control**: Application-level role checks (patient/doctor/admin) control data access

---

## Migration Instructions

1. **For New Database**: Run `patient_database_schema.sql`
2. **For Existing Database**: Run `update_patient_schema.sql` to add new fields
3. **Backup First**: Always backup your database before running migrations
4. **Test in Development**: Test migrations on a copy of production data first

---

## Notes

- All timestamps use `CURRENT_TIMESTAMP` defaults
- All text fields use `utf8mb4` encoding for full Unicode support
- Foreign keys use `ON DELETE CASCADE` to maintain referential integrity
- The `radiology_files` table is created dynamically by the application if it doesn't exist
- MRI analysis is performed automatically on image uploads

---

## Future Enhancements

Consider adding:
- Patient insurance information
- Medical history timeline view
- Appointment reminders system
- Prescription refill tracking
- Lab result trend analysis
- Integration with external medical systems (HL7, FHIR)

