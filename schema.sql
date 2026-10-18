-- OFFTRAIL normalized MySQL 8 / MariaDB schema
CREATE DATABASE IF NOT EXISTS offtrail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE offtrail;
CREATE TABLE IF NOT EXISTS users (
 user_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 username VARCHAR(40) NOT NULL, username_normalized VARCHAR(40) NOT NULL,
 email VARCHAR(254) NOT NULL, password_hash VARCHAR(255) NOT NULL,
 role ENUM('user','reviewer','admin') NOT NULL DEFAULT 'user',
 email_verified_at DATETIME NULL, is_active BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE KEY uq_users_username (username_normalized), UNIQUE KEY uq_users_email (email),
 KEY idx_users_role (role)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS otp_verifications (
 otp_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL,
 otp_hash VARCHAR(255) NOT NULL, purpose ENUM('verify_email','password_reset') NOT NULL,
 expires_at DATETIME NOT NULL, consumed_at DATETIME NULL, failed_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 resend_count SMALLINT UNSIGNED NOT NULL DEFAULT 0, window_started_at DATETIME NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT fk_otp_user FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
 KEY idx_otp_user_purpose (user_id,purpose,expires_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS auth_sessions (
 session_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL,
 token_hash CHAR(64) NOT NULL UNIQUE, expires_at DATETIME NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT fk_session_user FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
 KEY idx_sessions_expiry(expires_at), KEY idx_sessions_user(user_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS categories (
 category_id SMALLINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(60) NOT NULL UNIQUE, slug VARCHAR(60) NOT NULL UNIQUE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS user_preferences (
 user_id BIGINT UNSIGNED NOT NULL, category_id SMALLINT UNSIGNED NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,category_id),
 FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
 FOREIGN KEY(category_id) REFERENCES categories(category_id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS places (
 place_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, name VARCHAR(150) NOT NULL,
 category_id SMALLINT UNSIGNED NOT NULL, description TEXT NOT NULL,
 latitude DECIMAL(10,7) NULL, longitude DECIMAL(10,7) NULL,
 origin_region ENUM('Dehradun','Haridwar','Rishikesh','Other') NOT NULL DEFAULT 'Other',
 difficulty ENUM('Easy','Easy-moderate','Moderate','Difficult','Unknown') NOT NULL DEFAULT 'Unknown',
 duration_min_minutes SMALLINT UNSIGNED NULL, duration_max_minutes SMALLINT UNSIGNED NULL,
 transport_notes VARCHAR(500) NULL, safety_notes TEXT NULL,
 verification_status ENUM('pending','verified','rejected') NOT NULL DEFAULT 'pending',
 verified_by BIGINT UNSIGNED NULL, verified_at DATETIME NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 FOREIGN KEY(category_id) REFERENCES categories(category_id), FOREIGN KEY(verified_by) REFERENCES users(user_id) ON DELETE SET NULL,
 KEY idx_places_category_status (category_id,verification_status), KEY idx_places_region (origin_region,verification_status), KEY idx_places_verified_at (verified_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS routes (
 route_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, place_id BIGINT UNSIGNED NOT NULL,
 origin_name VARCHAR(120) NOT NULL, destination_name VARCHAR(150) NOT NULL,
 transport_mode ENUM('public_transport','two_wheeler','car','walking','mixed','unknown') NOT NULL DEFAULT 'unknown',
 route_notes TEXT NULL, source_url VARCHAR(1000) NULL, source_note VARCHAR(500) NULL,
 last_updated DATE NULL, status ENUM('verified','estimated','unavailable') NOT NULL DEFAULT 'unavailable',
 FOREIGN KEY(place_id) REFERENCES places(place_id) ON DELETE CASCADE,
 KEY idx_routes_place_mode(place_id,transport_mode)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS price_estimates (
 price_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, place_id BIGINT UNSIGNED NULL, route_id BIGINT UNSIGNED NULL,
 expense_type ENUM('transport','food','stay','entry','activity','other') NOT NULL,
 amount DECIMAL(10,2) NULL, currency CHAR(3) NOT NULL DEFAULT 'INR', unit_label VARCHAR(80) NULL,
 source_url VARCHAR(1000) NULL, source_note VARCHAR(500) NULL, last_updated DATE NULL,
 confidence_status ENUM('sourced','estimated','unavailable') NOT NULL DEFAULT 'unavailable',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(place_id) REFERENCES places(place_id) ON DELETE CASCADE,
 FOREIGN KEY(route_id) REFERENCES routes(route_id) ON DELETE CASCADE,
 CONSTRAINT chk_price_target CHECK (place_id IS NOT NULL OR route_id IS NOT NULL),
 CONSTRAINT chk_price_amount CHECK ((confidence_status='unavailable' AND amount IS NULL) OR (confidence_status<>'unavailable' AND amount IS NOT NULL AND amount>=0)),
 KEY idx_price_place_type(place_id,expense_type,last_updated), KEY idx_price_route_type(route_id,expense_type,last_updated)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS trips (
 trip_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL,
 title VARCHAR(150) NOT NULL DEFAULT 'My OFFTRAIL trip', origin_name VARCHAR(150) NOT NULL,
 duration_value DECIMAL(6,2) NOT NULL, duration_unit ENUM('hours','days') NOT NULL,
 group_size SMALLINT UNSIGNED NOT NULL DEFAULT 1, budget DECIMAL(10,2) NOT NULL DEFAULT 0,
 transport_mode VARCHAR(40) NOT NULL DEFAULT 'any', status ENUM('draft','planned','completed','cancelled') NOT NULL DEFAULT 'draft',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
 CONSTRAINT chk_trip_group CHECK(group_size>0), CONSTRAINT chk_trip_budget CHECK(budget>=0), KEY idx_trips_user_date(user_id,created_at)
) ENGINE=InnoDB;
-- Persistent request queue: limits are enforced transactionally against the user row.
CREATE TABLE IF NOT EXISTS trip_requests (
 request_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 user_id BIGINT UNSIGNED NOT NULL,
 destination VARCHAR(150) NOT NULL,
 travel_date DATE NOT NULL,
 travellers SMALLINT UNSIGNED NOT NULL DEFAULT 1,
 guide_units SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 vehicle_units SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 allocated_permits SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 allocated_guides SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 allocated_vehicles SMALLINT UNSIGNED NOT NULL DEFAULT 0,
 status ENUM('PENDING','PROCESSING','WAITING_RESOURCE','APPROVED','REJECTED') NOT NULL DEFAULT 'PENDING',
 submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 decided_by BIGINT UNSIGNED NULL,
 decided_at DATETIME NULL,
 resources_released_at DATETIME NULL,
 decision_note VARCHAR(500) NULL,
 FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
 FOREIGN KEY(decided_by) REFERENCES users(user_id) ON DELETE SET NULL,
 KEY idx_request_queue(status,travel_date,submitted_at),
 KEY idx_request_owner(user_id,status,submitted_at),
 CONSTRAINT chk_request_people CHECK(travellers BETWEEN 1 AND 30),
 CONSTRAINT chk_request_permit_allocation CHECK(allocated_permits <= travellers),
 CONSTRAINT chk_request_guide_allocation CHECK(allocated_guides <= guide_units),
 CONSTRAINT chk_request_vehicle_allocation CHECK(allocated_vehicles <= vehicle_units)
) ENGINE=InnoDB;
-- Capacity is a configurable planning/demo inventory, not a live supplier booking feed.
CREATE TABLE IF NOT EXISTS resource_inventory (
 inventory_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 destination VARCHAR(150) NOT NULL,
 travel_date DATE NOT NULL,
 permit_capacity SMALLINT UNSIGNED NOT NULL DEFAULT 20,
 guide_capacity SMALLINT UNSIGNED NOT NULL DEFAULT 5,
 vehicle_capacity SMALLINT UNSIGNED NOT NULL DEFAULT 3,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 UNIQUE KEY uq_inventory_destination_date(destination,travel_date)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS trip_items (
 trip_item_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, trip_id BIGINT UNSIGNED NOT NULL,
 place_id BIGINT UNSIGNED NOT NULL, item_order SMALLINT UNSIGNED NOT NULL,
 reason TEXT NULL, estimated_total DECIMAL(10,2) NULL, estimate_status ENUM('sourced','estimated','unavailable') NOT NULL DEFAULT 'unavailable',
 UNIQUE KEY uq_trip_place_order(trip_id,item_order), FOREIGN KEY(trip_id) REFERENCES trips(trip_id) ON DELETE CASCADE,
 FOREIGN KEY(place_id) REFERENCES places(place_id), KEY idx_trip_items_place(place_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS visits (
 user_id BIGINT UNSIGNED NOT NULL, place_id BIGINT UNSIGNED NOT NULL,
 visited BOOLEAN NOT NULL DEFAULT FALSE, visited_at DATETIME NULL, notes VARCHAR(1000) NULL,
 PRIMARY KEY(user_id,place_id), FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
 FOREIGN KEY(place_id) REFERENCES places(place_id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS photos (
 photo_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL,
 place_id BIGINT UNSIGNED NOT NULL, storage_key VARCHAR(500) NOT NULL,
 mime_type VARCHAR(80) NOT NULL, byte_size BIGINT UNSIGNED NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE, FOREIGN KEY(place_id) REFERENCES places(place_id) ON DELETE CASCADE,
 KEY idx_photos_owner_place(user_id,place_id), CONSTRAINT chk_photo_size CHECK(byte_size<=10485760)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS submissions (
 submission_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, submitter_id BIGINT UNSIGNED NOT NULL,
 reviewer_id BIGINT UNSIGNED NULL, suggested_name VARCHAR(150) NOT NULL, category_id SMALLINT UNSIGNED NOT NULL,
 description TEXT NOT NULL, coordinates_text VARCHAR(1000) NULL, route_notes TEXT NULL,
 status ENUM('pending','approved','rejected','changes_requested') NOT NULL DEFAULT 'pending', review_notes TEXT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at DATETIME NULL,
 FOREIGN KEY(submitter_id) REFERENCES users(user_id) ON DELETE CASCADE, FOREIGN KEY(reviewer_id) REFERENCES users(user_id) ON DELETE SET NULL,
 FOREIGN KEY(category_id) REFERENCES categories(category_id), KEY idx_submissions_status_date(status,created_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS submission_photos (
 submission_photo_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, submission_id BIGINT UNSIGNED NOT NULL,
 storage_key VARCHAR(500) NOT NULL, mime_type VARCHAR(80) NOT NULL, byte_size BIGINT UNSIGNED NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(submission_id) REFERENCES submissions(submission_id) ON DELETE CASCADE,
 KEY idx_submission_photos_submission(submission_id), CONSTRAINT chk_submission_photo_size CHECK(byte_size<=524288)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS audit_log (
 audit_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, actor_user_id BIGINT UNSIGNED NULL,
 action_name VARCHAR(80) NOT NULL, entity_name VARCHAR(80) NOT NULL, entity_id VARCHAR(80) NULL,
 detail_json JSON NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(actor_user_id) REFERENCES users(user_id) ON DELETE SET NULL, KEY idx_audit_entity(entity_name,entity_id), KEY idx_audit_date(created_at)
) ENGINE=InnoDB;
INSERT IGNORE INTO categories(name,slug) VALUES
 ('Trekking','trekking'),('Travel','travel'),('Cafés','cafes'),('Fun activities','fun-activities'),('Nearby activities','nearby-activities');
-- Seed records are explicitly demo catalogue entries. Verify all details before publishing to production.
INSERT INTO places(name,category_id,description,origin_region,difficulty,verification_status,verified_at)
SELECT 'George Everest Estate',category_id,'Short uphill walk with views over the Doon Valley. Check access and conditions locally.','Dehradun','Easy-moderate','pending',NULL FROM categories WHERE slug='trekking'
AND NOT EXISTS(SELECT 1 FROM places WHERE name='George Everest Estate');
INSERT INTO places(name,category_id,description,origin_region,difficulty,verification_status,verified_at)
SELECT 'Maldevta',category_id,'Riverside scenery close to Dehradun; respect local access and water-safety guidance.','Dehradun','Easy','pending',NULL FROM categories WHERE slug='nearby-activities'
AND NOT EXISTS(SELECT 1 FROM places WHERE name='Maldevta');
INSERT INTO places(name,category_id,description,origin_region,difficulty,verification_status,verified_at)
SELECT 'Kunjapuri viewpoint',category_id,'Himalayan viewpoint; confirm road and weather conditions before travel.','Rishikesh','Easy-moderate','pending',NULL FROM categories WHERE slug='travel'
AND NOT EXISTS(SELECT 1 FROM places WHERE name='Kunjapuri viewpoint');
CREATE OR REPLACE VIEW verified_places AS SELECT p.place_id,p.name,c.name AS category,p.description,p.origin_region,p.difficulty,p.latitude,p.longitude FROM places p JOIN categories c ON c.category_id=p.category_id WHERE p.verification_status='verified';
