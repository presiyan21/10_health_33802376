// db.js

// Load environment variables
require('dotenv').config()
const mysql = require('mysql2/promise')

// MySQL2 promise-based pool setup
const pool = mysql.createPool({
  host: process.env.HEALTH_HOST || 'localhost',
  user: process.env.HEALTH_USER || 'health_app',
  password: process.env.HEALTH_PASSWORD || 'qwertyuiop',
  database: process.env.HEALTH_DATABASE || 'health',
  waitForConnections: true,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT) || 10,
  queueLimit: 0,
  decimalNumbers: true
})

// Test connection at startup
async function testConnection() {
  let conn
  try {
    conn = await pool.getConnection()
    await conn.ping()
    conn.release()
    console.log('MySQL: pool connected successfully')
  } catch (err) {
    if (conn) try { conn.release() } catch (_) {}
    console.error('MySQL: connection test failed:', err.message || err)
    throw err
  }
}

module.exports = { pool, testConnection }
