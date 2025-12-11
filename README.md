# Health & Fitness Tracker

A compact fitness-tracking web app built with Node.js, Express and EJS. It lets users log workouts, share posts, upload GPX files, and manage their accounts with secure authentication and TOTP verification.

## Features
- Personal workout dashboard with pagination  
- Add, edit, search and export workouts (CSV)  
- GPX upload with automatic parsing  
- Community posts with comments  
- Secure registration and login (bcrypt + TOTP)  
- Audit logging for login attempts  
- Admin panel for managing users  
- Weekly progress charts powered by Chart.js  
- Clean EJS-based UI and structured routes

## Tech Stack
- **Frontend:** HTML / EJS, CSS, Chart.js  
- **Backend:** Node.js, Express  
- **Database:** MySQL + mysql2  
- **Security:** bcrypt, csurf, Helmet, dotenv  
- **Uploads & parsing:** multer, xml2js  
- **TOTP:** speakeasy + qrcode  

## Getting Started

### 1. Clone the repo
```bash
git clone 
```

### Install dependencies
```bash
npm install
```

### 3. Set up environment
```bash
HEALTH_HOST=
HEALTH_USER=
HEALTH_PASSWORD=
HEALTH_DATABASE=
SESSION_SECRET=
HEALTH_BASE_PATH=
```

### 4. Prepare the database
```bash
create_db.sql
insert_test_data.sql
```

### 5. Start the server
Visit:
http://localhost:8000
