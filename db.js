import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const DB_PATH = path.join(DATA_DIR, 'visionaid.db');

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('VisionAid Database');
console.log('DB path:', DB_PATH);
console.log('DB exists:', fs.existsSync(DB_PATH));
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');


db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS profiles (
    owner_id TEXT PRIMARY KEY,
    language TEXT DEFAULT 'en',
    voice_speed REAL DEFAULT 0.9,
    focal_px REAL,
    high_contrast INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS locations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    lat REAL NOT NULL,
    lng REAL NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL,
    time TEXT NOT NULL,
    description TEXT,
    count INTEGER,
    closest_distance_m REAL,
    classes TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_history_owner ON history(owner_id);
  CREATE INDEX IF NOT EXISTS idx_locations_owner ON locations(owner_id);
`);

export default db;