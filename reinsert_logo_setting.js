const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const DATABASE_PATH = process.env.DATABASE_PATH || './pisowifi.db';

let db = new sqlite3.Database(DATABASE_PATH, (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log(`Connected to the database at ${DATABASE_PATH}`);
        db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, ['landing_logo', ''], function(err) {
            if (err) {
                console.error("Error re-inserting setting:", err.message);
            } else {
                console.log(`Setting 'landing_logo' re-inserted successfully (if it didn't exist). Rows affected: ${this.changes}`);
            }
            db.close((err) => {
                if (err) {
                    console.error(err.message);
                } else {
                    console.log('Database connection closed.');
                }
            });
        });
    }
});
