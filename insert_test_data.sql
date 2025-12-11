-- -----------------------
-- Health & Fitness App - Seed Data
-- -----------------------

USE health;
SET @now = NOW();

-- ===========================
-- 1. Users
-- ===========================
INSERT IGNORE INTO users (username, first_name, last_name, email, hashed_password, role, is_verified, created_at)
VALUES
  ('gold',  'Gillian', 'Oldman',  'gold@healthapp.local', '$2b$12$eWdJyHZ2BWJ20E09fhUY5.gMxdojUeLVb1xJ6zIC4AUc4EbYtfAhS', 'admin', 1, '2025-12-04 18:37:49'),
  ('alice', 'Alice',   'Example',  'alice@local',          '$2b$12$Wq3G1uL.Y0zI3V6tQ7q1suUxQ1m3bLxD5j4rFJ3jVqzj1l9W3x2y2', 'user', 1, '2025-11-15 09:00:00'),
  ('bob',   'Bob',     'Builder',  'bob@local',            '$2b$12$Wq3G1uL.Y0zI3V6tQ7q1suUxQ1m3bLxD5j4rFJ3jVqzj1l9W3x2y2', 'user', 1, '2025-11-16 10:00:00'),
  ('steve', 'Steve',   'Runner',   'steve@local',          '$2b$12$Wq3G1uL.Y0zI3V6tQ7q1suUxQ1m3bLxD5j4rFJ3jVqzj1l9W3x2y2', 'user', 1, '2025-12-06 21:50:00'),
  ('emma',  'Emma',    'Fit',      'emma@local',           '$2b$12$Wq3G1uL.Y0zI3V6tQ7q1suUxQ1m3bLxD5j4rFJ3jVqzj1l9W3x2y2', 'user', 1, '2025-11-30 08:30:00'),
  ('trainer_tom', 'Tom', 'Coach',  'tom@local',            '$2b$12$Wq3G1uL.Y0zI3V6tQ7q1suUxQ1m3bLxD5j4rFJ3jVqzj1l9W3x2y2', 'trainer', 1, '2025-11-01 12:00:00'),
  ('manager_mary', 'Mary', 'Manager','mary@local',          '$2b$12$Wq3G1uL.Y0zI3V6tQ7q1suUxQ1m3bLxD5j4rFJ3jVqzj1l9W3x2y2', 'manager', 1, '2025-10-10 08:00:00');

-- OPTIONAL: set a known TOTP secret for 'gold' for testing (base32). Remove in production.
UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP' WHERE username = 'gold';

-- ===========================
-- 2. Workouts
-- ===========================
INSERT INTO workouts (user_id, activity, activity_date, duration_mins, calories, notes, source, is_public, created_at)
VALUES
  ((SELECT id FROM users WHERE username='gold' LIMIT 1), 'Morning Run', '2025-11-20', 35, 300, 'Felt strong, intervals included', 'manual', 1, '2025-11-20 07:30:00'),
  ((SELECT id FROM users WHERE username='gold' LIMIT 1), 'Yoga', '2025-11-21', 45, 180, 'Flexibility focus', 'manual', 0, '2025-11-21 18:00:00'),
  ((SELECT id FROM users WHERE username='alice' LIMIT 1), 'Evening Walk', '2025-12-01', 30, 120, 'Relaxed pace', 'manual', 1, '2025-12-01 18:00:00'),
  ((SELECT id FROM users WHERE username='bob' LIMIT 1), 'Strength Training', '2025-11-25', 50, 350, 'Upper-body focus', 'manual', 1, '2025-11-25 10:00:00');

-- ===========================
-- 3. Community posts
-- ===========================
INSERT INTO posts (user_id, title, content, created_at)
VALUES
  ((SELECT id FROM users WHERE username='gold' LIMIT 1), 'Welcome to the community', 'Welcome! This is the public community for workout tips, events, and sharing progress. Say hi!', '2025-12-04 18:50:00'),
  ((SELECT id FROM users WHERE username='steve' LIMIT 1), 'Workout ideas', 'Looking for 30-minute HIIT routines that build speed. Any suggestions?', '2025-12-06 22:26:28');

-- ===========================
-- 4. Comments for posts
-- ===========================
INSERT INTO comments (post_id, user_id, content, created_at)
VALUES
  ((SELECT id FROM posts WHERE title='Welcome to the community' LIMIT 1),
   (SELECT id FROM users WHERE username='alice' LIMIT 1),
   'Hi all, so glad to be here!', '2025-12-04 19:00:00');

-- ===========================
-- 5. Audit log samples
-- ===========================
INSERT INTO audit_log (username, status, attempt_time)
VALUES
  ('gold', 'SUCCESS', '2025-12-04 18:38:00'),
  ('alice', 'SUCCESS', '2025-12-01 09:01:00'),
  ('unknown', 'FAILURE', '2025-12-05 11:11:00');

-- ===========================
-- 6. Final sanity check
-- ===========================
SELECT 'seed complete' AS note;
SELECT COUNT(*) AS users_total FROM users;
SELECT COUNT(*) AS workouts_total FROM workouts;
SELECT COUNT(*) AS posts_total FROM posts;
SELECT COUNT(*) AS post_comments_total FROM comments;
