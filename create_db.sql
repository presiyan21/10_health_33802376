-- -----------------------
-- Health & Fitness App DB
-- -----------------------

DROP DATABASE IF EXISTS `health`;
CREATE DATABASE `health` CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci;
USE `health`;

-- USERS table
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  hashed_password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'user',
  is_verified TINYINT(1) NOT NULL DEFAULT 0,
  verify_token VARCHAR(255) DEFAULT NULL,
  reset_token VARCHAR(255) DEFAULT NULL,
  reset_expires DATETIME DEFAULT NULL,
  totp_secret VARCHAR(255) DEFAULT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- WORKOUTS table
CREATE TABLE workouts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  activity VARCHAR(255) NOT NULL,
  activity_date DATE NOT NULL,
  duration_mins INT NOT NULL,
  calories INT DEFAULT NULL,
  notes TEXT,
  source VARCHAR(64) DEFAULT NULL,
  is_public TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_workouts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- POSTS table
CREATE TABLE posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  title VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_posts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- COMMENTS table
CREATE TABLE comments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  post_id INT DEFAULT NULL,
  workout_id INT DEFAULT NULL,
  user_id INT DEFAULT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_comments_post FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  CONSTRAINT fk_comments_workout FOREIGN KEY (workout_id) REFERENCES workouts(id) ON DELETE CASCADE,
  CONSTRAINT fk_comments_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ATTACHMENTS table
CREATE TABLE attachments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workout_id INT DEFAULT NULL,
  comment_id INT DEFAULT NULL,
  user_id INT DEFAULT NULL,
  filename VARCHAR(255) NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  mime VARCHAR(255),
  size INT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_attachments_workout FOREIGN KEY (workout_id) REFERENCES workouts(id) ON DELETE CASCADE,
  CONSTRAINT fk_attachments_comment FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE,
  CONSTRAINT fk_attachments_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- AUDIT LOG
CREATE TABLE audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100),
  status ENUM('SUCCESS','FAILURE') NOT NULL,
  attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Indexes
CREATE INDEX idx_workouts_activity ON workouts(activity);
CREATE INDEX idx_workouts_date ON workouts(activity_date);
CREATE INDEX idx_posts_user ON posts(user_id);
CREATE INDEX idx_comments_post ON comments(post_id);
CREATE INDEX idx_comments_workout ON comments(workout_id);
CREATE INDEX idx_attachments_workout ON attachments(workout_id);

