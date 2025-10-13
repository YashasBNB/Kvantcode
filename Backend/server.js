import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath);

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Add to .env

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'authorization header required' });
  }
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
};

const app = express();
const PORT = process.env.PORT || 3001;
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Live-switchable model (no restart needed)
let CURRENT_MODEL = process.env.BACKEND_DEFAULT_MODEL || "meta-llama/llama-4-maverick:free";
// Free fallback models to try when upstream is rate-limited (429)
const FREE_FALLBACK_MODELS = [
  'openai/gpt-oss-120b:free',
  'x-ai/grok-4-fast:free',
  'meta-llama/llama-4-maverick:free',
];
// Chat endpoint removed; OpenRouter config no longer required here.

// Initialize database tables
async function initDb() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Users table
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`, (err) => {
        if (err) reject(err);
      });

      // Usage table
      db.run(`CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        total_tokens INTEGER DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )`, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  });
}

// Removed role/persona inference helper previously used by /chat.

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', model: CURRENT_MODEL });
});

// Root: show which model this backend is configured to use
app.get('/', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Backend Status</title></head>
      <body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px;">
        <h2>Backend is running</h2>
        <p><strong>Model:</strong> <code>${CURRENT_MODEL}</code></p>
        <p>For JSON status see <a href="/health">/health</a>.</p>
      </body>
    </html>
  `);
});

// View current model (JSON)
app.get('/model', (_req, res) => {
  res.json({ model: CURRENT_MODEL });
});

// Change current model at runtime (requires auth)
app.post('/model', authMiddleware, (req, res) => {
  const { model } = req.body || {};
  if (!model || typeof model !== 'string' || !model.trim()) {
    return res.status(400).json({ error: 'invalid_model' });
  }
  CURRENT_MODEL = model.trim();
  console.log(`[backend] CURRENT_MODEL updated to "${CURRENT_MODEL}" by user ${req.user?.id ?? 'unknown'}`);
  res.json({ ok: true, model: CURRENT_MODEL });
});

// POST /v1/chat/completions (OpenAI-style, non-streaming)
// Body: { model: string, messages: [{ role: 'user'|'system'|'assistant', content: string }], temperature?: number, max_tokens?: number }
app.post('/v1/chat/completions', authMiddleware, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({ error: 'missing_api_key', details: 'Set OPENROUTER_API_KEY in backend/.env' });
    }

    let { model = CURRENT_MODEL, messages, temperature = 0.7, max_tokens, stream } = req.body || {};
    // map placeholder model to the live current model
    if (model === 'backend-default') model = CURRENT_MODEL;
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array is required' });
    }

    const makeRequest = async (useModel, doStream) => fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'http://localhost',
        'X-Title': 'backend-server'
      },
      body: JSON.stringify({
        model: useModel,
        messages,
        temperature,
        ...(max_tokens ? { max_tokens } : {}),
        ...(doStream ? { stream: true } : {})
      }),
    });

    const wantsStream = Boolean(stream) || String(req.query.stream || '').toLowerCase() === 'true'
    console.log(`[backend] /v1/chat/completions model="${model}" wantsStream=${wantsStream}`)
    let rsp = await makeRequest(model, wantsStream);

    if (!rsp.ok) {
      const text = await rsp.text().catch(() => '');
      // Fallback retry: if upstream says model unsupported, try CURRENT_MODEL once
      const isNoEndpoint404 = rsp.status === 404 && /No endpoints found/i.test(text || '');
      const isRateLimited429 = rsp.status === 429 || /rate[-\s]?limited|temporarily rate-limited/i.test(text || '');

      if (isNoEndpoint404 && model !== CURRENT_MODEL) {
        console.warn(`Upstream 404 for model "${model}". Retrying with CURRENT_MODEL: ${CURRENT_MODEL}`);
        rsp = await makeRequest(CURRENT_MODEL, wantsStream);
        if (!rsp.ok) {
          const text2 = await rsp.text().catch(() => '');
          return res.status(rsp.status).json({ error: 'upstream_error', details: text2 });
        }
      }
      else if (isRateLimited429) {
        // brief backoff and retry with a different free model
        const tryOrder = [CURRENT_MODEL, ...FREE_FALLBACK_MODELS].filter((m, i, a) => m && a.indexOf(m) === i);
        const next = tryOrder.find(m => m !== model);
        if (next) {
          console.warn(`Upstream 429 for model "${model}". Retrying once with fallback model: ${next}`);
          await new Promise(r => setTimeout(r, 600));
          rsp = await makeRequest(next, wantsStream);
          if (!rsp.ok) {
            const text2 = await rsp.text().catch(() => '');
            return res.status(rsp.status).json({ error: 'upstream_error', details: text2 });
          }
        } else {
          return res.status(rsp.status).json({ error: 'upstream_error', details: text });
        }
      }
      else {
        return res.status(rsp.status).json({ error: 'upstream_error', details: text });
      }
    }

    if (wantsStream) {
      // Proxy SSE stream as-is
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      const reader = rsp.body;
      reader.on('data', (chunk) => {
        res.write(chunk);
      });
      reader.on('end', () => {
        res.end();
      });
      reader.on('error', (e) => {
        try { res.end(); } catch {}
      });
      return;
    } else {
      const data = await rsp.json();
      // return OpenAI-style response as-is
      return res.json(data);
    }
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', details: String(err) });
  }
});

// POST /signup
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'password must be at least 6 characters' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'invalid email format' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    return new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [name, email, passwordHash],
        function(err) {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
              return resolve(res.status(409).json({ error: 'email already exists' }));
            }
            return resolve(res.status(500).json({ error: 'database error' }));
          }
          const userId = this.lastID;
          const token = jwt.sign({ id: userId, email }, JWT_SECRET);
          resolve(res.json({ token, user: { id: userId, name, email } }));
        }
      );
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// POST /login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
          return resolve(res.status(500).json({ error: 'database error' }));
        }
        if (!user) {
          return resolve(res.status(401).json({ error: 'invalid email or password' }));
        }
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
          return resolve(res.status(401).json({ error: 'invalid email or password' }));
        }
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
        resolve(res.json({ token, user: { id: user.id, name: user.name, email: user.email } }));
      });
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// GET /usage
app.get('/usage', authMiddleware, async (req, res) => {
  try {
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT SUM(input_tokens) AS total_input_tokens, SUM(output_tokens) AS total_output_tokens, SUM(total_tokens) AS total_tokens FROM usage WHERE user_id = ?',
        [req.user.id],
        (err, row) => {
          if (err) {
            return resolve(res.status(500).json({ error: 'database error' }));
          }
          resolve(res.json({
            total_input_tokens: row.total_input_tokens || 0,
            total_output_tokens: row.total_output_tokens || 0,
            total_tokens: row.total_tokens || 0
          }));
        }
      );
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

// Initialize database and start server
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}).catch((err) => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
