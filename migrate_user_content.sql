USE offtrail;

-- Make room for full Google Maps URLs on existing installs.
ALTER TABLE submissions MODIFY coordinates_text VARCHAR(1000) NULL;

-- Enforce the application upload cap in MySQL as well.
ALTER TABLE photos DROP CHECK chk_photo_size;
ALTER TABLE photos ADD CONSTRAINT chk_photo_size CHECK(byte_size<=524288);

-- Photo metadata is stored in MySQL; photo bytes live in the project's uploads/ directory.
CREATE TABLE IF NOT EXISTS submission_photos (
 submission_photo_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 submission_id BIGINT UNSIGNED NOT NULL,
 storage_key VARCHAR(500) NOT NULL,
 mime_type VARCHAR(80) NOT NULL,
 byte_size BIGINT UNSIGNED NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(submission_id) REFERENCES submissions(submission_id) ON DELETE CASCADE,
 KEY idx_submission_photos_submission(submission_id),
 CONSTRAINT chk_submission_photo_size CHECK(byte_size<=524288)
) ENGINE=InnoDB;
