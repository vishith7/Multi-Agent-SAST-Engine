const express = require('express');
const mysql = require('mysql');
const app = express();

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'test_db'
});

app.get('/unsafe-sql', (req, res) => {
    // Taint source
    const userId = req.query.id;
    
    // Taint flow
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    // Taint sink
    db.query(query, (error, results) => {
        if (error) throw error;
        res.send(results);
    });
});

app.listen(3000, () => {
    console.log('Server listening on port 3000');
});
