const mysql = require("mysql2");

const connection = mysql.createConnection({
  // host: '127.0.0.1',
  // port: '3306',
  host: process.env.DB_HOST,
  port: process.env.PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

module.exports = connection;