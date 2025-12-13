# Health & Fitness Tracker

Fitness-tracking web app built with Node.js, Express and EJS. It lets users log workouts, share posts, upload GPX files, and manage their accounts with secure authentication and TOTP verification.

## Features
- Personal workout dashboard with pagination  
- Add, edit, search and export workouts (CSV)  
- GPX upload   
- Community posts with comments  
- Secure registration and login 
- Audit logging for login attempts  
- Admin panel for managing users  
- Weekly progress charts powered by Chart.js  

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
git clone https://github.com/presiyan21/10_health_33802376
```

### Install dependencies
```bash
npm install
```

### 3. Set up environment
```bash
HEALTH_HOST=localhost
HEALTH_USER=health_app
HEALTH_PASSWORD=qwertyuiop
HEALTH_DATABASE=health
HEALTH_BASE_PATH=http://localhost:8000

PORT=8000
SESSION_SECRET=verysecretpleasechange
```

### 4. Prepare the database
```bash
create_db.sql
insert_test_data.sql
```

### 5. Start the server
Visit:
http://localhost:8000
