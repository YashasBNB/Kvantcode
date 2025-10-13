import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath);

db.all(`
  SELECT user_id, SUM(input_tokens) AS total_input, SUM(output_tokens) AS total_output, SUM(total_tokens) AS total
  FROM usage
  GROUP BY user_id
`, [], (err, rows) => {
  if (err) {
    console.error('Error:', err);
  } else {
    console.log('Token usage per user:');
    rows.forEach(row => {
      console.log(`User ID: ${row.user_id}`);
      console.log(`  Total input tokens: ${row.total_input || 0}`);
      console.log(`  Total output tokens: ${row.total_output || 0}`);
      console.log(`  Total tokens: ${row.total || 0}`);
      console.log('');
    });
    if (rows.length === 0) {
      console.log('No usage records found.');
    }
  }
  db.close();
});
