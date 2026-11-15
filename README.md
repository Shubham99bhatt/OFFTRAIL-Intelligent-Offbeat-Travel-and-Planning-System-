# OFFTRAIL — Intelligent Offbeat Travel & Planning System

A starter implementation based on the supplied 30-slide project blueprint. The dashboard is a responsive web UI, the API server is written in **C**, the relational schema targets **MySQL/MariaDB**, and the OS demonstration engine is written in C. The provided Himalayan temple image is the fixed full-screen background across the dashboard; panels are translucent overlays so the image remains visible.

## Important implementation status

This package is a **working foundation, not a finished production service**. The C server supports static frontend delivery, `/api/health`, a database-backed `/api/places` endpoint, and database-backed account signup/sign-in/sign-out. Passwords are stored as salted PBKDF2-SHA256 hashes and sign-in sessions are stored as hashes in `auth_sessions`. Email OTP delivery/verification, password reset, photo uploads, user-owned trip persistence, moderation APIs, and production security hardening are not implemented. Signup activates the account immediately; configure and implement email verification before treating accounts as verified. The dashboard can be previewed in static mode. The expanded catalogue seed rows are `pending` and the API returns them with `verified=false`, clearly labelled for local verification; rejected records are excluded.

## Folder structure

- `frontend/` — HTML, CSS, JavaScript and the supplied permanent background image.
- `backend/src/server.c` — C HTTP server process with a bounded FCFS request queue, four concurrent OS worker threads, per-worker MySQL/MariaDB connections, static assets and API routes.
- `backend/src/os_api.c` — C-backed OS Lab simulations exposed to the website at `/api/os/*`; Producer–Consumer uses actual OS threads, semaphores and a mutex.
- `backend/CMakeLists.txt` — build configuration for the MySQL/MariaDB Connector/C library.
- `database/schema.sql` — normalized relational schema, constraints, indexes, view and pending sample submissions.
- `os_engine/os_engine.c` — interactive CPU scheduling, Banker’s safety/resource-request checks, deadlock detection, fixed-partition memory allocation, and threaded producer-consumer synchronization.
- `docs/` — implementation notes and test checklist.
- `scripts/` — Windows helper scripts.

## 1. Prerequisites (Windows 11)

1. Install a C compiler (MinGW-w64 UCRT64 or Visual Studio Build Tools) and CMake.
2. Install MySQL Server or MariaDB Server, plus the matching **Connector/C development headers and library**. Windows uses the built-in CNG/Bcrypt library for password hashing; Linux/macOS builds also need OpenSSL Crypto development files.
3. Create a local database user with limited privileges. Avoid using the `root` account for the app.
4. Keep database credentials in environment variables, never in source control.

## 2. Create the database

Run `database/schema.sql` in MySQL Workbench or the MySQL/MariaDB command-line client. The schema creates database `offtrail`. The starter seed rows are pending review. The expanded user-supplied catalogue is in `database/seed_uttarakhand_catalogue.sql` and is intentionally pending review (not represented as independently verified). Import that file after the schema. It contains 70 travel destinations, 70 trekking listings grouped by difficulty, 90 cafe/food listings (30 each for Dehradun, Haridwar and Rishikesh), and 30 fun/adventure activities. Walking, Parks and Clubs are not offered as discovery categories.

Example local environment (PowerShell, adapt the connector installation paths to your machine):

```powershell
$env:MYSQL_HOST = '127.0.0.1'
$env:MYSQL_USER = 'offtrail_app'
$env:MYSQL_PASSWORD = 'YOUR_LOCAL_PASSWORD'
$env:MYSQL_DATABASE = 'offtrail'
```

## 3. Build and run the C API server

From the `OFFTRAIL` project directory, configure CMake with the actual Connector/C paths if CMake cannot find them automatically:

```powershell
cmake -S backend -B backend/build -DMYSQL_INCLUDE_DIR='C:/path/to/include' -DMYSQL_LIBRARY='C:/path/to/lib/libmariadb.dll.a'
cmake --build backend/build --config Release
Copy-Item backend\build\offtrail_server.exe backend\build\offtrail_server_dual.exe -Force
```

From `backend/build`, run `offtrail_server_dual.exe` for the user site on `http://localhost:5000`. In another terminal with the same MySQL environment variables, run `offtrail_server_dual.exe --owner` for the owner service on `http://localhost:5001`. Both instances use the same database and frontend folder; the owner instance only serves the owner dashboard and review APIs.

Check `http://localhost:5000/api/health`. A disconnected database returns `503` for `/api/places`; health reports the degraded state. The server logs a database connection failure rather than pretending the database is available.

## 4. Run the OS workbench

The backend CMake build creates `offtrail_server.exe` and `offtrail_os_engine.exe`; the copy command above creates the dual-port server executable. From the project root, open a second VS Code terminal and run:

```powershell
..\backend\build\offtrail_os_engine.exe
```

The menu includes FCFS, SJF, SRTF, Round Robin, non-preemptive and preemptive Priority, Banker’s safety and request checks, deadlock detection, First/Best/Worst Fit memory allocation, and a producer-consumer exercise using actual OS threads, counting semaphores and a mutex. These are educational simulations and do not change Windows' real process scheduler or memory manager. See `OS_CONCEPTS.md` for the algorithms and what each option demonstrates.

## 5. Current API routes

- `GET /api/health` — C process and database connection status.
- `GET /api/places` — reads non-rejected catalogue records from MySQL/MariaDB and includes an explicit `verificationStatus`/`verified` field; pending records are shown as catalogue listings requiring local verification.
- `GET /` and frontend asset paths — serves the web client.
- `POST /api/auth/signup` — validates the username, email and strong password policy, rejects duplicate usernames/emails, and stores a salted PBKDF2-SHA256 password hash.
- `POST /api/auth/login` — checks credentials and returns a random bearer token; only its SHA-256 hash is stored in `auth_sessions` (seven-day expiry).
- `POST /api/auth/logout` — revokes the bearer token in the database.

## 6. Blueprint requirements for the next implementation phase

- Email OTP only (no SMS); minimum 2-minute validity, countdown in UI, one-time server-side use, maximum 5 resends in a defined rate-limit window, failed-attempt limits and cooldown. Never display the OTP on the website.
- Secure salted password hashing, parameterized SQL, unique normalized usernames, roles and ownership checks.
- Preference rows, top 3 per selected category where enough approved records exist, feasibility-first filtering, transparent score explanation and honest missing-data handling.
- Save trip + itinerary + cost estimate in a transaction; record price source and last-updated date. Unknown costs must be `Unavailable` or explicitly `Estimated`, never fabricated as exact.
- Google Maps destination-specific URL links only; no claim that OFFTRAIL calculates live travel time/distance.
- Visit checklist, optional photo storage with type/size validation and ownership checks, community submissions held pending review, reviewer/admin audit trail.
- Additional OS workbench topics can include disk scheduling (FCFS/SSTF/SCAN), paging/page replacement, and richer resource-allocation visualizations.
- DBMS demonstration: ER diagram, normalization, PK/FK/UNIQUE/CHECK constraints, indexes and query plans, joins, transactions/rollback, isolation/locking, views, audit and appropriate triggers.
- Verify deployment and persistence on the actual public HTTPS URL before describing the project as deployed.

## Privacy and deployment

This is a local development starter. Do not expose it publicly as-is: the HTTP server is intentionally minimal and not hardened for hostile traffic. Add robust request parsing, TLS termination, authentication/authorization, rate limiting, CSRF/CORS policy, secure password hashing, OTP provider integration, logging hygiene, backups and full test coverage before deployment. Free-tier eligibility, quotas, storage persistence and email delivery must be checked against current provider terms.


## Expanded Uttarakhand catalogue (reviewed update)

1. Import `database/schema.sql` if creating a fresh database.
2. Import `database/seed_uttarakhand_catalogue.sql` into the existing `offtrail` database to add the supplied lists idempotently.
3. Run `database/migrate_user_content.sql` from the project root for an existing database; it adds hidden-place photo metadata and applies the per-photo size limit.
4. Restart the C server from `backend/build` so the relative frontend path remains valid.
5. Open `http://localhost:5000` and refresh with `Ctrl+Shift+R`. The existing design, styling, and supplied Himalayan background asset are preserved.

Signed-in users see their own request history and an **Approved Requests** section with the approved destinations and their trip tools. The site-owner `admin` account signs in to the separate `http://localhost:5001` owner service, which contains only the global Trip requests and Hidden place requests queues. The backend verifies the owner role for dashboard session checks, queue access, protected proof photos, and all review actions; the public user service on port 5000 does not expose owner review pages or actions. Approved visitors can mark places visited and optionally attach up to two JPEG photos (minimum 640×480, maximum 512 KB each). Users can suggest a hidden place with its category and Google Maps link; its description and up to two proof photos are optional. Suggestions enter a separate owner-only priority queue and appear in the catalogue after approval.

The cafe list is tagged by the city supplied in the request. Difficulty labels for treks are preliminary grouping labels based on the user's supplied sections; they are not a substitute for route-specific official grading, current weather, permits, or guide advice. The current cost endpoint deliberately returns `Unavailable` until a price with source/date is entered.

**Authentication limitation:** signup and login work against MySQL/MariaDB, but email OTP is not wired up in this package and signup activates accounts immediately. Do not describe email addresses as verified or use this as a public production service until email verification and remaining security controls are implemented.

## OS concepts in the project

The public frontend does not expose an OS Lab. The C code still demonstrates CPU scheduling, Banker-style resource safety, deadlock analysis and the synchronized request worker pool; see `OS_CONCEPTS.md` and `docs/TRIP_REQUEST_OS_WORKFLOW.md` for their role and limits.

## Persistent trip request queue (OS/DBMS workflow)

Signed-in users select a listed destination and submit travel date, travellers, and optional guide/vehicle demand. The backend transactionally allows at most three active requests per user. Requests waiting at least 24 hours move ahead of all newer requests, with the oldest aged request first; younger requests sort by nearest travel date. Reviewers must process the queue head. Budget, visited and directions tools unlock only for a destination with an `APPROVED` request. Configure reviewer role and demo resource capacities using `docs/TRIP_REQUEST_OS_WORKFLOW.md`. Requests and their states are stored in MySQL (`trip_requests`); inventory is configurable demo planning data, not live supplier availability.
