-- Run once from the project root on an existing OFFTRAIL database.
-- Conditional additions also support databases where an earlier Banker build
-- already added one or more allocation columns.
USE offtrail;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns
 WHERE table_schema=DATABASE() AND table_name='trip_requests' AND column_name='allocated_permits')=0,
 'ALTER TABLE trip_requests ADD COLUMN allocated_permits SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER vehicle_units',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns
 WHERE table_schema=DATABASE() AND table_name='trip_requests' AND column_name='allocated_guides')=0,
 'ALTER TABLE trip_requests ADD COLUMN allocated_guides SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER allocated_permits',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns
 WHERE table_schema=DATABASE() AND table_name='trip_requests' AND column_name='allocated_vehicles')=0,
 'ALTER TABLE trip_requests ADD COLUMN allocated_vehicles SMALLINT UNSIGNED NOT NULL DEFAULT 0 AFTER allocated_guides',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.columns
 WHERE table_schema=DATABASE() AND table_name='trip_requests' AND column_name='resources_released_at')=0,
 'ALTER TABLE trip_requests ADD COLUMN resources_released_at DATETIME NULL AFTER decided_at',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;

-- Preserve already-approved requests as holding their complete claims.
UPDATE trip_requests
 SET allocated_permits=travellers, allocated_guides=guide_units, allocated_vehicles=vehicle_units
 WHERE status='APPROVED' AND resources_released_at IS NULL
   AND allocated_permits=0 AND allocated_guides=0 AND allocated_vehicles=0;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.table_constraints
 WHERE constraint_schema=DATABASE() AND table_name='trip_requests' AND constraint_name='chk_request_permit_allocation')=0,
 'ALTER TABLE trip_requests ADD CONSTRAINT chk_request_permit_allocation CHECK(allocated_permits <= travellers)',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.table_constraints
 WHERE constraint_schema=DATABASE() AND table_name='trip_requests' AND constraint_name='chk_request_guide_allocation')=0,
 'ALTER TABLE trip_requests ADD CONSTRAINT chk_request_guide_allocation CHECK(allocated_guides <= guide_units)',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;

SET @ddl = IF((SELECT COUNT(*) FROM information_schema.table_constraints
 WHERE constraint_schema=DATABASE() AND table_name='trip_requests' AND constraint_name='chk_request_vehicle_allocation')=0,
 'ALTER TABLE trip_requests ADD CONSTRAINT chk_request_vehicle_allocation CHECK(allocated_vehicles <= vehicle_units)',
 'SELECT 1');
PREPARE banker_stmt FROM @ddl; EXECUTE banker_stmt; DEALLOCATE PREPARE banker_stmt;
