import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath);

db.all('SELECT id, name, email FROM users', [], (err, rows) => {
  if (err) {
    console.error('Error:', err);
  } else {
    console.log(`Total users: ${rows.length}`);
    rows.forEach(row => {
      console.log(`- ID: ${row.id}, Name: ${row.name}, Email: ${row.email}`);
    });
  }
  db.close();
});
