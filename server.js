import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from './db.js';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me-in-production';
function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '15mb' }));

app.use((req, res, next) => {
  req.deviceId = req.header('x-device-id') || 'anonymous';
  next();
});

// Attaches req.userId if a valid JWT is present — logged-in requests get
// their own data keyed by account instead of just this browser's device id.
// Invalid/missing token = anonymous, not an error, so the app still works
// without logging in.
app.use((req, res, next) => {
  const authHeader = req.header('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(authHeader.slice(7), JWT_SECRET);
      req.userId = payload.uid;
      req.userEmail = payload.email;
    } catch { /* expired/invalid — fall through as anonymous */ }
  }
  next();
});

// Every route below uses this instead of req.deviceId directly — logged-in
// users get a stable identity across devices, anonymous users still work
// exactly as before, scoped to their browser's device id.
function ownerId(req) {
  return req.userId ? `user:${req.userId}` : req.deviceId;
}

// Enforced server-side — a direct API call (bypassing the frontend's login
// gate) still can't touch personal data without a valid account. The
// frontend gate is a UX convenience; this is the actual enforcement.
function requireAuth(req, res, next) {
  if (!req.userId) return res.status(401).json({ success: false, error: 'Login required' });
  next();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only image files allowed'));
    cb(null, true);
  },
});
const uploadAudio = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.get('/api/health', async (req, res) => {
  res.json({ status: 'ok', service: 'VisionAid Proxy' });
});

// NOTE: the old /api/detect route that proxied to a Python YOLO service is
// gone along with that service. Detection is fully client-side now
// (frontend/src/lib/detector.js, onnxruntime-web) — no server round-trip
// needed for object detection itself. The only thing still hitting the
// server for a "scan" is the AI scene description below, and that's Groq
// vision, not the old Python model.


// ============================================================================
// AUTH — signup / login / me
// ============================================================================
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password required'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 6 characters'
    });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    const existing = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(normalizedEmail);

    if (existing) {
      console.log(`⚠️ Signup attempted for existing user: ${normalizedEmail}`);

      return res.status(409).json({
        success: false,
        error: 'An account with that email already exists'
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const info = db
      .prepare(`
        INSERT INTO users (email, password_hash, name)
        VALUES (?, ?, ?)
      `)
      .run(
        normalizedEmail,
        passwordHash,
        name?.trim() || null
      );

    const user = {
      id: Number(info.lastInsertRowid),
      email: normalizedEmail,
      name: name?.trim() || null
    };

    console.log(`✅ User created: ${user.email} [ID ${user.id}]`);

    return res.status(201).json({
      success: true,
      token: signToken(user),
      user
    });

  } catch (error) {
    console.error('❌ SIGNUP DATABASE ERROR:', error);

    return res.status(500).json({
      success: false,
      error: 'Could not create account'
    });
  }
});
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password required'
    });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    const user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(normalizedEmail);

    if (!user) {
      console.log(`❌ Login failed — user not found: ${normalizedEmail}`);

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      console.log(`❌ Login failed — incorrect password: ${normalizedEmail}`);

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    const safeUser = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    console.log(`✅ User logged in: ${user.email} [ID ${user.id}]`);

    return res.json({
      success: true,
      token: signToken(safeUser),
      user: safeUser
    });

  } catch (error) {
    console.error('❌ LOGIN DATABASE ERROR:', error);

    return res.status(500).json({
      success: false,
      error: 'Could not log in'
    });
  }
});

app.get('/api/auth/me', (req, res) => {
  if (!req.userId) return res.status(401).json({ success: false, error: 'Not logged in' });
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(401).json({ success: false, error: 'Account no longer exists' });
  res.json({ success: true, user });
});

// ============================================================================
// SCAN HISTORY — SQLite, scoped to ownerId (account if logged in, else device)
// ============================================================================
app.post('/api/history', requireAuth, (req, res) => {
  const { description, count, closest_distance_m, classes } = req.body || {};
  const oid = ownerId(req);
  try {
    db.prepare('INSERT INTO history (owner_id, time, description, count, closest_distance_m, classes) VALUES (?, ?, ?, ?, ?, ?)')
      .run(oid, new Date().toISOString(), description || null, count ?? null, closest_distance_m ?? null, JSON.stringify(classes || []));
    // keep only the most recent 200 rows per owner
    db.prepare(`
      DELETE FROM history WHERE owner_id = ? AND id NOT IN (
        SELECT id FROM history WHERE owner_id = ? ORDER BY id DESC LIMIT 200
      )
    `).run(oid, oid);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/history', requireAuth, (req, res) => {
  const limit = Number(req.query.limit) || 50;
  const rows = db.prepare('SELECT time, description, count, closest_distance_m, classes FROM history WHERE owner_id = ? ORDER BY id DESC LIMIT ?').all(ownerId(req), limit);
  res.json({ success: true, history: rows.map(r => ({ ...r, classes: JSON.parse(r.classes || '[]') })) });
});

app.delete('/api/history', requireAuth, (req, res) => {
  db.prepare('DELETE FROM history WHERE owner_id = ?').run(ownerId(req));
  res.json({ success: true });
});

app.get('/api/stats', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT classes, closest_distance_m FROM history WHERE owner_id = ?').all(ownerId(req));
  const classCounts = {};
  let closestEver = null;
  for (const r of rows) {
    for (const c of JSON.parse(r.classes || '[]')) classCounts[c] = (classCounts[c] || 0) + 1;
    if (r.closest_distance_m != null && (closestEver === null || r.closest_distance_m < closestEver)) closestEver = r.closest_distance_m;
  }
  const topClasses = Object.entries(classCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([cls, count]) => ({ cls, count }));
  res.json({ success: true, total_scans: rows.length, top_classes: topClasses, closest_object_ever_m: closestEver });
});

// ============================================================================
// PROFILE / SETTINGS — SQLite
// ============================================================================
app.get('/api/profile', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM profiles WHERE owner_id = ?').get(ownerId(req));
  const profile = row
    ? { language: row.language, voiceSpeed: row.voice_speed, focalPx: row.focal_px, highContrast: !!row.high_contrast }
    : { name: 'Guest', language: 'en', voiceSpeed: 0.9, highContrast: false };
  res.json({ success: true, profile });
});

app.put('/api/profile', requireAuth, (req, res) => {
  const oid = ownerId(req);
  const { language, voiceSpeed, focalPx, highContrast } = req.body || {};
  db.prepare(`
    INSERT INTO profiles (owner_id, language, voice_speed, focal_px, high_contrast, updated_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(owner_id) DO UPDATE SET
      language = COALESCE(?, language),
      voice_speed = COALESCE(?, voice_speed),
      focal_px = COALESCE(?, focal_px),
      high_contrast = COALESCE(?, high_contrast),
      updated_at = CURRENT_TIMESTAMP
  `).run(
    oid, language ?? null, voiceSpeed ?? null, focalPx ?? null, highContrast == null ? null : (highContrast ? 1 : 0),
    language ?? null, voiceSpeed ?? null, focalPx ?? null, highContrast == null ? null : (highContrast ? 1 : 0)
  );
  const row = db.prepare('SELECT * FROM profiles WHERE owner_id = ?').get(oid);
  res.json({ success: true, profile: { language: row.language, voiceSpeed: row.voice_speed, focalPx: row.focal_px, highContrast: !!row.high_contrast } });
});

// ============================================================================
// SAVED LOCATIONS — SQLite
// ============================================================================
app.get('/api/locations', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, name, lat, lng FROM locations WHERE owner_id = ? ORDER BY created_at').all(ownerId(req));
  res.json({ success: true, locations: rows });
});

app.post('/api/locations', requireAuth, (req, res) => {
  const { name, lat, lng } = req.body || {};
  if (!name || lat == null || lng == null) return res.status(400).json({ success: false, error: 'name, lat, lng required' });
  const id = Date.now().toString(36);
  db.prepare('INSERT INTO locations (id, owner_id, name, lat, lng) VALUES (?, ?, ?, ?, ?)').run(id, ownerId(req), name, lat, lng);
  res.json({ success: true, location: { id, name, lat, lng } });
});

app.delete('/api/locations/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM locations WHERE id = ? AND owner_id = ?').run(req.params.id, ownerId(req));
  res.json({ success: true });
});

function haversineBearing(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  const distance_m = R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const y = Math.sin(dLng) * Math.cos(toRad(lat2));
  const x = Math.cos(toRad(lat1)) * Math.sin(toRad(lat2)) - Math.sin(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.cos(dLng);
  let bearing_deg = (Math.atan2(y, x) * 180) / Math.PI;
  bearing_deg = (bearing_deg + 360) % 360;
  const dirs = ['north', 'northeast', 'east', 'southeast', 'south', 'southwest', 'west', 'northwest'];
  const compass = dirs[Math.round(bearing_deg / 45) % 8];
  return { distance_m, bearing_deg, compass };
}

app.get('/api/direction', (req, res) => {
  const { locationId, lat, lng } = req.query;
  if (lat == null || lng == null) return res.status(400).json({ success: false, error: 'current lat/lng required' });
  const target = db.prepare('SELECT * FROM locations WHERE id = ? AND owner_id = ?').get(locationId, ownerId(req));
  if (!target) return res.status(404).json({ success: false, error: 'Saved location not found' });
  const { distance_m, bearing_deg, compass } = haversineBearing(Number(lat), Number(lng), target.lat, target.lng);
  res.json({ success: true, location: target, distance_m: Math.round(distance_m), bearing_deg: Math.round(bearing_deg), compass, sentence: `${target.name} is about ${Math.round(distance_m)} meters to the ${compass}.` });
});

app.post('/api/sos', (req, res) => {
  const { message, lat, lng, description, lang } = req.body || {};
  const timestamp = new Date().toISOString();
  const locationLine = (lat && lng) ? `https://maps.google.com/?q=${lat},${lng}` : 'unavailable';
  console.log(`🚨 SOS: ${timestamp} | loc: ${locationLine} | scene: ${description || 'n/a'} | msg: ${message || 'triggered'} | lang: ${lang || 'en'}`);
  res.json({ success: true, logged: true });
});

// ============================================================================
// KEY ROTATION — FIXED
// ----------------------------------------------------------------------------
// Old approach: one comma-packed env var (GROQ_API_KEYS="key1,key2,key3").
// Problem you hit: still one Groq ORG behind all those keys in many free-tier
// setups, so the 8000 TPM cap is shared and burns out just as fast.
// New approach: each key lives in its OWN numbered env var, so you can mix
// keys from DIFFERENT Groq accounts/orgs (each with its own separate 8000
// TPM budget) instead of one account's keys pretending to be a "pool".
//   GROQ_API_KEY_1=gsk_xxx   (account A)
//   GROQ_API_KEY_2=gsk_yyy   (account B)
//   GROQ_API_KEY_3=gsk_zzz   (account C)
// Old GROQ_API_KEYS="a,b,c" style still works too (backward compatible).
// Same pattern for GEMINI_API_KEY_1..N / GEMINI_API_KEYS.
// ============================================================================
function keyPool(prefix) {
  const keys = [];
  // numbered vars: PREFIX_1, PREFIX_2, ... PREFIX_20 (stop at first gap after 20)
  for (let i = 1; i <= 20; i++) {
    const v = process.env[`${prefix}_${i}`];
    if (v) keys.push(v.trim());
  }
  // backward-compat: comma list in PREFIX + "S", e.g. GROQ_API_KEYS
  const csv = process.env[`${prefix}S`];
  if (csv) keys.push(...csv.split(',').map(k => k.trim()).filter(Boolean));
  // also allow a bare single PREFIX (no number) as a 1-key fallback
  const single = process.env[prefix];
  if (single) keys.push(single.trim());
  return [...new Set(keys)]; // dedupe
}
const rotationIndex = {};
function nextKey(prefix) {
  const pool = keyPool(prefix);
  if (!pool.length) return null;
  rotationIndex[prefix] = (rotationIndex[prefix] ?? -1) + 1;
  return pool[rotationIndex[prefix] % pool.length];
}
function poolSize(prefix) { return keyPool(prefix).length; }

function stripThinking(text) {
  if (/<think>/i.test(text) && !/<\/think>/i.test(text)) return '';
  return text.replace(/<think>[\s\S]*?<\/think>/gi, '').replace(/^\s*Thinking:[\s\S]*?\n\n/i, '').trim();
}

async function callGroqVision(dataUrl, systemPrompt, userPrompt) {
  const tries = Math.max(1, poolSize('GROQ_API_KEY'));
  for (let i = 0; i < tries; i++) {
    const key = nextKey('GROQ_API_KEY');
    if (!key) break;
    try {
      const r = await axios.post('https://api.groq.com/openai/v1/chat/completions', {
        model: 'qwen/qwen3.6-27b',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: [{ type: 'text', text: userPrompt }, { type: 'image_url', image_url: { url: dataUrl } }] },
        ],
        max_tokens: 220, // trimmed from 400 — image is now resized client-side too, so total tokens per call are much lower
        temperature: 0.3,
        reasoning_format: 'hidden',
      }, { headers: { Authorization: `Bearer ${key}` }, timeout: 20000 });
      const cleaned = stripThinking(r.data.choices[0].message.content.trim());
      if (!cleaned) continue;
      return cleaned;
    } catch (e) {
      console.error(`Groq vision error [key #${i + 1}/${tries}]:`, e.response?.status, e.response?.data?.error?.message || e.message);
      if (e.response?.status !== 429) throw e;
      // 429 → this key/org is out of budget, loop tries the NEXT distinct env var's key
    }
  }
  return null;
}

async function callGeminiVision(base64, mimeType, systemPrompt, userPrompt) {
  const tries = Math.max(1, poolSize('GEMINI_API_KEY'));
  for (let i = 0; i < tries; i++) {
    const key = nextKey('GEMINI_API_KEY');
    if (!key) break;
    try {
      const r = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,
        { contents: [{ parts: [{ text: `${systemPrompt}\n\n${userPrompt}` }, { inline_data: { mime_type: mimeType, data: base64 } }] }] },
        { timeout: 15000 }
      );
      return stripThinking(r.data.candidates[0].content.parts[0].text.trim());
    } catch (e) {
      console.error(`Gemini vision error [key #${i + 1}/${tries}]:`, e.response?.status, e.response?.data?.error?.message || e.message);
      if (e.response?.status !== 429) throw e;
    }
  }
  return null;
}

// Per-device cooldown — describe-scene is the expensive call (image tokens
// are the bulk of the 8000 TPM org cap, not the text). Rapid repeat taps
// were burning the budget in under a minute even with "8 keys" because
// they're all the same org. This is the real fix for that, not more keys.
const DESCRIBE_COOLDOWN_MS = 4000;
const lastDescribeAt = {};

app.post('/api/describe-scene', (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message });
    if (!req.file) return res.status(400).json({ success: false, error: 'No image received' });

    const now = Date.now();
    const waitedMs = now - (lastDescribeAt[req.deviceId] || 0);
    if (waitedMs < DESCRIBE_COOLDOWN_MS) {
      const fallback = req.body.fallback_description;
      if (fallback) return res.json({ success: true, description: fallback, provider: 'on-device-fallback', cooldown: true });
      return res.status(429).json({ success: false, error: `Wait ${Math.ceil((DESCRIBE_COOLDOWN_MS - waitedMs) / 1000)}s between AI scene descriptions` });
    }
    lastDescribeAt[req.deviceId] = now;

    const lang = req.body.lang === 'hi' ? 'hi' : 'en';
    const dataUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    const base64 = req.file.buffer.toString('base64');

    const systemPrompt =
      `You are a real-time OUTDOOR navigation assistant for a blind pedestrian, describing whatever camera view you're given. ` +
      `Describe the scene in 2-3 short, concrete sentences, prioritizing: road surface hazards (potholes, cracks, uneven pavement, ` +
      `open drains, curbs, steps), moving traffic (cars, bikes, motorcycles, buses), and static obstacles (walls, poles, trees, parked ` +
      `vehicles, construction barriers). Always end with one clear recommended action (stop, proceed straight, move left/right, wait). ` +
      `${lang === 'hi'
        ? 'Write your ENTIRE answer only in Hindi using Devanagari script. Do not use any English words or Latin letters anywhere.'
        : 'Respond only in English.'} ` +
      `Output nothing but the description itself — no preamble, no labels, no meta-commentary, no <think> tags.`;
    const userPrompt = lang === 'hi' ? 'इस दृश्य का हिंदी में वर्णन करें, सड़क के खतरों पर ध्यान दें।' : 'Describe this outdoor scene, focusing on path hazards.';
    const hasDevanagari = (s) => /[\u0900-\u097F]/.test(s);

    try {
      let description = await callGroqVision(dataUrl, systemPrompt, userPrompt);
      let provider = 'groq';
      if (!description) {
        description = await callGeminiVision(base64, req.file.mimetype, systemPrompt, userPrompt);
        provider = 'gemini';
      }
      if (description && lang === 'hi' && !hasDevanagari(description)) {
        const retryPrompt = systemPrompt + ' REMINDER: Devanagari script only, no exceptions.';
        const retried = await callGroqVision(dataUrl, retryPrompt, userPrompt) || await callGeminiVision(base64, req.file.mimetype, retryPrompt, userPrompt);
        if (retried && hasDevanagari(retried)) description = retried;
      }
      if (!description) {
        const fallback = req.body.fallback_description;
        if (fallback) {
          return res.json({ success: true, description: fallback, provider: 'on-device-fallback' });
        }
        const groqCount = poolSize('GROQ_API_KEY');
        const geminiCount = poolSize('GEMINI_API_KEY');
        const reason = (groqCount + geminiCount === 0)
          ? 'No GROQ_API_KEY_1 / GEMINI_API_KEY_1 (etc) set in backend/.env — restart server after editing .env'
          : `All configured keys are rate-limited on the SAME org quota (multiple keys from one Groq account share one 8000 TPM cap) — check server console`;
        return res.status(503).json({ success: false, error: reason });
      }
      res.json({ success: true, description, provider });
    } catch (e) {
      res.status(500).json({ success: false, error: e.response?.data?.error?.message || e.message });
    }
  });
});

app.post('/api/voice-intent', async (req, res) => {
  const { transcript, lang } = req.body || {};
  if (!transcript) return res.status(400).json({ success: false, error: 'transcript required' });

  const prompt =
    'Classify the user\'s spoken command into exactly one JSON object: {"intent":"analyze|describe|read_text|sos|navigate|mute|unmute|settings|stats|crossing|history|map|chat","target":"<location name if navigate, else empty>"}. ' +
    'Output ONLY the JSON, nothing else, no markdown fences. "analyze"=asking what\'s around/in front right now. "describe"=asking for a rich AI scene description. ' +
    '"read_text"=asking to read a sign/text/label. "sos"=asking for help/emergency/danger. "navigate"=asking to go/walk somewhere specific (extract place name into target). ' +
    '"mute"/"unmute"=asking to turn voice output on/off. "settings"=asking to open settings/preferences. "stats"=asking for usage stats/dashboard. ' +
    '"crossing"=asking if there\'s a zebra crossing/crosswalk ahead. "history"=asking to hear the scan log/what happened before. "map"=asking to open the map or set a waypoint. ' +
    '"chat"=ANY other question. Default to "chat" when unsure, never "unknown".\n\n' +
    `Command: "${transcript}"`;

  try {
    const key = nextKey('GEMINI_API_KEY');
    if (!key) return res.status(500).json({ success: false, error: 'No Gemini key configured' });

    const r = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key=${key}`,
      { contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0 } },
      { timeout: 6000 }
    );
    const raw = stripThinking(r.data.candidates[0].content.parts[0].text.trim());
    const parsed = JSON.parse(raw.replace(/```json|```/g, '').trim());
    res.json({ success: true, ...parsed });
  } catch (e) {
    res.status(500).json({ success: false, error: e.response?.data?.error?.message || e.message });
  }
});

// ---- Voice: transcription — moved to GEMINI, not Groq. Groq's TPM budget
// is now reserved entirely for describe-scene (the image calls); every
// small text/audio call competing for the same pool was part of what burned
// through it so fast. Gemini 2.0 Flash accepts audio as inline_data the
// same way describe-scene sends images, so no separate Whisper call needed —
// one request both transcribes AND can answer, but we keep it factual/literal
// here (transcription only) and let /api/chat do the answering.
app.post('/api/transcribe', (req, res) => {
  uploadAudio.single('audio')(req, res, async (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message });
    if (!req.file) return res.status(400).json({ success: false, error: 'No audio received' });

    const key = nextKey('GEMINI_API_KEY');
    if (!key) return res.status(500).json({ success: false, error: 'No Gemini key configured — set GEMINI_API_KEY_1 in .env' });

    const lang = req.body.lang === 'hi' ? 'hi' : 'en';
    const base64 = req.file.buffer.toString('base64');
    const mimeType = req.file.mimetype || 'audio/webm';

    try {
      // Full "flash" (not lite) for audio input — lite tiers are text/image
      // focused and inconsistent with audio in practice; this call is rare
      // (once per question) so the slightly heavier model is worth it.
      const r = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,
        {
          contents: [{
            parts: [
              { text: `Transcribe this audio EXACTLY as spoken, in ${lang === 'hi' ? 'Hindi (Devanagari script)' : 'English'}. Output ONLY the transcribed words, nothing else — no preamble, no quotes.` },
              { inline_data: { mime_type: mimeType, data: base64 } },
            ],
          }],
        },
        { timeout: 15000 }
      );
      const text = stripThinking(r.data.candidates[0].content.parts[0].text.trim());
      res.json({ success: true, text });
    } catch (e) {
      console.error('Transcribe error:', e.response?.data?.error?.message || e.message);
      res.status(500).json({ success: false, error: e.response?.data?.error?.message || e.message });
    }
  });
});

// ---- Voice: free-form chat — GEMINI LITE (cheap text-only model, separate
// from both the Groq image budget and the heavier Gemini audio call above).
app.post('/api/chat', async (req, res) => {
  const { question, context, lang } = req.body || {};
  if (!question) return res.status(400).json({ success: false, error: 'question required' });

  const key = nextKey('GEMINI_API_KEY');
  if (!key) return res.status(500).json({ success: false, error: 'No Gemini key configured' });

  const prompt =
    `You are a friendly voice assistant for a blind pedestrian's navigation app. Answer naturally and briefly ` +
    `(2-4 sentences max, this gets read aloud by text-to-speech). If the question is about their surroundings, ` +
    `use this context if relevant: "${context || 'no recent scan available'}". Otherwise answer as a normal helpful ` +
    `assistant would. ${lang === 'hi' ? 'Reply only in Hindi (Devanagari script).' : 'Reply only in English.'} ` +
    `No preamble.\n\nQuestion: ${question}`;

  try {
    const r = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key=${key}`,
      { contents: [{ parts: [{ text: prompt }] }] },
      { timeout: 10000 }
    );
    const answer = stripThinking(r.data.candidates[0].content.parts[0].text.trim());
    res.json({ success: true, answer: answer || (lang === 'hi' ? 'माफ़ करें, जवाब नहीं मिला' : "Sorry, I didn't get an answer") });
  } catch (e) {
    console.error('Chat error:', e.response?.data?.error?.message || e.message);
    res.status(500).json({ success: false, error: e.response?.data?.error?.message || e.message });
  }
});

app.post('/api/directions', async (req, res) => {
  const { originLat, originLng, destLat, destLng, locationId } = req.body || {};
  let dLat = destLat, dLng = destLng;

  if (locationId) {
    const loc = db.prepare('SELECT * FROM locations WHERE id = ? AND owner_id = ?').get(locationId, ownerId(req));
    if (!loc) return res.status(404).json({ success: false, error: 'Saved location not found' });
    dLat = loc.lat; dLng = loc.lng;
  }
  if (dLat == null || dLng == null || originLat == null || originLng == null) {
    return res.status(400).json({ success: false, error: 'origin and destination required' });
  }

  const googleKey = process.env.GOOGLE_MAPS_API_KEY;
  if (googleKey) {
    try {
      const url = `https://maps.googleapis.com/maps/api/directions/json?origin=${originLat},${originLng}&destination=${dLat},${dLng}&mode=walking&key=${googleKey}`;
      const r = await axios.get(url, { timeout: 8000 });
      if (r.data.status === 'OK') {
        const leg = r.data.routes[0].legs[0];
        const steps = leg.steps.map(s => ({
          instruction: s.html_instructions.replace(/<[^>]+>/g, ''),
          distance_m: s.distance.value, distance_text: s.distance.text,
          end: s.end_location,
        }));
        return res.json({ success: true, provider: 'google', distance_text: leg.distance.text, duration_text: leg.duration.text, steps, polyline: r.data.routes[0].overview_polyline?.points || null });
      }
      console.warn('Google Directions failed:', r.data.status, '— falling back to ORS');
    } catch (e) {
      console.warn('Google Directions error:', e.message, '— falling back to ORS');
    }
  }

  const orsKey = process.env.ORS_API_KEY;
  if (orsKey) {
    try {
      const r = await axios.post(
        'https://api.openrouteservice.org/v2/directions/foot-walking/geojson',
        { coordinates: [[originLng, originLat], [dLng, dLat]] },
        { headers: { Authorization: orsKey }, timeout: 8000 }
      );
      const feature = r.data.features[0];
      const segment = feature.properties.segments[0];
      const coords = feature.geometry.coordinates;
      const steps = segment.steps.map(s => ({
        instruction: s.instruction,
        distance_m: Math.round(s.distance),
        distance_text: `${Math.round(s.distance)}m`,
        end: { lat: coords[s.way_points[1]][1], lng: coords[s.way_points[1]][0] },
      }));
      return res.json({
        success: true, provider: 'ors',
        distance_text: `${Math.round(segment.distance)}m`,
        duration_text: `${Math.round(segment.duration / 60)} min`,
        steps,
        path: coords.map(c => ({ lat: c[1], lng: c[0] })),
      });
    } catch (e) {
      console.warn('ORS error:', e.message, '— falling back to OSRM');
    }
  }

  // ---- OSRM public demo server — NO SIGNUP, NO API KEY, works right now ----
  // This is the fix for "ORS won't send verification email, Google key won't
  // work" — OSRM's demo instance is free and keyless. Fair-use rate limited
  // and not for production traffic, but perfectly fine for a college project
  // demo. Swap to your own OSRM instance later if you ever need to scale.
  try {
    const url = `https://router.project-osrm.org/route/v1/foot/${originLng},${originLat};${dLng},${dLat}?overview=full&geometries=geojson&steps=true`;
    const r = await axios.get(url, { timeout: 10000 });
    if (r.data.code !== 'Ok') throw new Error(r.data.message || 'OSRM route not found');
    const route = r.data.routes[0];
    const leg = route.legs[0];
    const steps = leg.steps.map(s => ({
      instruction: describeOsrmStep(s),
      distance_m: Math.round(s.distance),
      distance_text: `${Math.round(s.distance)}m`,
      end: { lat: s.maneuver.location[1], lng: s.maneuver.location[0] },
    }));
    return res.json({
      success: true, provider: 'osrm',
      distance_text: `${Math.round(route.distance)}m`,
      duration_text: `${Math.round(route.duration / 60)} min`,
      steps,
      path: route.geometry.coordinates.map(c => ({ lat: c[1], lng: c[0] })),
    });
  } catch (e) {
    // last-resort: no routing provider reachable at all — client falls back
    // to a straight-line compass bearing (see WaypointMap "GO DIRECT" mode)
    return res.status(502).json({ success: false, error: 'No routing provider reachable (ORS/Google/OSRM all failed) — use straight-line GO DIRECT mode instead', straight_line_available: true });
  }
});

function describeOsrmStep(step) {
  const type = step.maneuver.type;
  const modifier = step.maneuver.modifier;
  const name = step.name || 'the path';
  if (type === 'arrive') return 'You have arrived';
  if (type === 'depart') return `Head ${modifier || 'forward'} on ${name}`;
  if (modifier) return `Turn ${modifier} onto ${name}`;
  return `Continue on ${name}`;
}

app.listen(PORT, () => {
  console.log(`🚀 VisionAid Node.js Proxy running on http://localhost:${PORT}`);
 // console.log(`💾 Data dir: ${DATA_DIR}`);
  console.log(`🔑 GROQ keys loaded (vision only): ${poolSize('GROQ_API_KEY')}`);
  console.log(`🔑 GEMINI keys loaded (chat/transcribe/intent): ${poolSize('GEMINI_API_KEY')}`);
  console.log(`🗺️  GOOGLE_MAPS_API_KEY set: ${!!process.env.GOOGLE_MAPS_API_KEY}`);
  console.log(`🗺️  ORS_API_KEY set: ${!!process.env.ORS_API_KEY} (OSRM free fallback always available)`);
});