const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
        return;
    }
    
    db.all("SELECT * FROM requests", [], (err, rows) => {
        if (err) {
            console.error('Error querying requests:', err.message);
        } else {
            console.log("Current rows in 'requests' table:", rows);
        }
        
        db.all("SELECT id, username, role, status FROM users", [], (err, userRows) => {
            console.log("Current rows in 'users' table:", userRows);
            db.close();
        });
    });
});