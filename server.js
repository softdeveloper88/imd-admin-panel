require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFile } = require('child_process');
const AdmZip = require('adm-zip');
const initSqlJs = require('sql.js');
const cors = require('cors');
const zlib = require('zlib');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;
const execFileAsync = promisify(execFile);

const AUTH_COOKIE_NAME = 'imd_admin_auth';
const AUTH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const ADMIN_SETTINGS_PATH = path.join(__dirname, 'admin-settings.json');
const DEFAULT_ADMIN_USERNAME = process.env.IMD_ADMIN_USERNAME || process.env.ADMIN_USERNAME || 'admin';
const DEFAULT_ADMIN_PASSWORD = process.env.IMD_ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || 'admin123';
const DEFAULT_ADMIN_COOKIE_SECRET = process.env.IMD_ADMIN_COOKIE_SECRET || process.env.ADMIN_COOKIE_SECRET || crypto.randomBytes(24).toString('hex');
const PASSWORD_HASH_ITERATIONS = 120000;
const PASSWORD_HASH_LENGTH = 32;
const PASSWORD_HASH_DIGEST = 'sha256';

let adminSettingsCache = null;

let SQL;

function hashAdminPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(password), salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_LENGTH, PASSWORD_HASH_DIGEST).toString('hex');
  return { salt, hash };
}

function verifyAdminPassword(password, passwordSalt, passwordHash) {
  if (!passwordSalt || !passwordHash) return false;
  const computed = crypto.pbkdf2Sync(String(password), passwordSalt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_LENGTH, PASSWORD_HASH_DIGEST).toString('hex');
  const left = Buffer.from(computed, 'hex');
  const right = Buffer.from(String(passwordHash), 'hex');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function buildDefaultAdminSettings() {
  const passwordRecord = hashAdminPassword(DEFAULT_ADMIN_PASSWORD);
  return {
    username: DEFAULT_ADMIN_USERNAME,
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    cookieSecret: DEFAULT_ADMIN_COOKIE_SECRET,
    updatedAt: new Date().toISOString(),
  };
}

function normalizeAdminSettings(rawSettings) {
  const settings = rawSettings && typeof rawSettings === 'object' ? rawSettings : {};
  const username = String(settings.username || '').trim() || DEFAULT_ADMIN_USERNAME;
  const cookieSecret = String(settings.cookieSecret || '').trim() || DEFAULT_ADMIN_COOKIE_SECRET;
  const passwordSalt = String(settings.passwordSalt || '').trim();
  const passwordHash = String(settings.passwordHash || '').trim();

  if (passwordSalt && passwordHash) {
    return {
      username,
      passwordSalt,
      passwordHash,
      cookieSecret,
      updatedAt: settings.updatedAt || new Date().toISOString(),
    };
  }

  return buildDefaultAdminSettings();
}

function writeAdminSettings(settings) {
  adminSettingsCache = normalizeAdminSettings(settings);
  fs.writeFileSync(ADMIN_SETTINGS_PATH, `${JSON.stringify(adminSettingsCache, null, 2)}\n`, 'utf-8');
  return adminSettingsCache;
}

function getAdminSettings() {
  if (adminSettingsCache) return adminSettingsCache;

  if (!fs.existsSync(ADMIN_SETTINGS_PATH)) {
    return writeAdminSettings(buildDefaultAdminSettings());
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(ADMIN_SETTINGS_PATH, 'utf-8'));
    adminSettingsCache = normalizeAdminSettings(parsed);
  } catch (_) {
    adminSettingsCache = buildDefaultAdminSettings();
    writeAdminSettings(adminSettingsCache);
  }

  return adminSettingsCache;
}

function updateAdminSettings(changes) {
  const current = getAdminSettings();
  const next = {
    ...current,
    username: changes.username != null ? String(changes.username).trim() : current.username,
    cookieSecret: changes.cookieSecret != null ? String(changes.cookieSecret).trim() : current.cookieSecret,
    updatedAt: new Date().toISOString(),
  };

  if (changes.password) {
    const passwordRecord = hashAdminPassword(changes.password);
    next.passwordSalt = passwordRecord.salt;
    next.passwordHash = passwordRecord.hash;
  }

  return writeAdminSettings(next);
}

function usesDefaultAdminPassword() {
  const settings = getAdminSettings();
  return verifyAdminPassword(DEFAULT_ADMIN_PASSWORD, settings.passwordSalt, settings.passwordHash);
}

// ----- Encryption -----
const SECRET = Buffer.from('hs;d,hghdk[;ak', 'utf-8');
const IV = Buffer.from([17, 115, 105, 102, 103, 104, 111, 107, 108, 122, 120, 119, 118, 98, 110, 109]);

function makeSalt(name) {
  let s = Buffer.from(name, 'utf-8');
  while (s.length < 8) s = Buffer.concat([s, Buffer.from(' ')]);
  return s;
}

function deriveKey(salt) {
  return crypto.pbkdf2Sync(SECRET, salt, 19, 16, 'sha1');
}

function aesDecrypt(data, key) {
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, IV);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function decryptText(base64Data, saltStr) {
  const data = Buffer.from(base64Data, 'base64');
  const key = deriveKey(makeSalt(saltStr));
  const decrypted = aesDecrypt(data, key);
  return zlib.gunzipSync(decrypted).toString('utf-8');
}

function decryptMedia(data, filename) {
  const key = deriveKey(makeSalt(filename));
  return aesDecrypt(data, key);
}

// ----- sql.js helpers -----
function openDb(dbPath) {
  return new SQL.Database(fs.readFileSync(dbPath));
}

function dbAll(db, sql, params) {
  const stmt = db.prepare(sql);
  if (params) stmt.bind(params);
  const results = [];
  while (stmt.step()) results.push(stmt.getAsObject());
  stmt.free();
  return results;
}

function dbGet(db, sql, params) {
  const r = dbAll(db, sql, params);
  return r.length > 0 ? r[0] : null;
}

function hasTable(db, tableName) {
  return !!dbGet(db, "SELECT name FROM sqlite_master WHERE type='table' AND name = $name", { $name: tableName });
}

function tryDecryptOrReturnRaw(data, saltStr) {
  if (typeof data !== 'string') return '';
  if (data.trim().startsWith('<')) return data;

  try {
    return decryptText(data, saltStr);
  } catch (e) {
    return data;
  }
}

function getTableColumns(db, tableName) {
  if (!hasTable(db, tableName)) return [];
  return dbAll(db, `PRAGMA table_info("${tableName}")`).map(col => col.name);
}

function rewritePackageHtml(html, pkgName, docPath = '') {
  if (!html) return '';

  let workingHtml = String(html)
    .replace(/<\?xml[\s\S]*?\?>/gi, '')
    .replace(/<!DOCTYPE[\s\S]*?>/gi, '')
    .trim();

  const headMatch = workingHtml.match(/<head[^>]*>([\s\S]*?)<\/head>/i);
  const bodyMatch = workingHtml.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  if (bodyMatch) {
    const headContent = headMatch ? headMatch[1] : '';
    workingHtml = `${headContent}${bodyMatch[1]}`;
  }

  const imageExts = new Set(['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.bmp']);
  const baseDir = docPath ? path.posix.dirname(normalizeUploadPath(docPath)) : '';

  const rewritePath = rawValue => {
    if (!rawValue) return rawValue;
    if (/^(?:[a-z]+:)?\/\//i.test(rawValue)) return rawValue;
    if (/^(data:|mailto:|tel:|javascript:|#)/i.test(rawValue)) return rawValue;

    const match = rawValue.match(/^([^?#]+)([?#].*)?$/);
    const pathPart = match ? match[1] : rawValue;
    const suffix = match ? match[2] || '' : '';

    let normalized = normalizeUploadPath(pathPart);
    if (!normalized) return rawValue;

    if (!pathPart.startsWith('/')) {
      normalized = normalizeUploadPath(path.posix.normalize(baseDir ? path.posix.join(baseDir, pathPart) : pathPart));
    }

    normalized = normalized.replace(/^(\.\.\/)+/, '');
    const ext = path.posix.extname(normalized).toLowerCase();

    if (imageExts.has(ext)) {
      return `/api/packages/${encodeURIComponent(pkgName)}/media/${encodeURIComponent(path.posix.basename(normalized))}${suffix}`;
    }

    return `/api/packages/${encodeURIComponent(pkgName)}/file/${encodeURI(normalized)}${suffix}`;
  };

  let rewritten = workingHtml.replace(/(src|href)=("([^"]*)"|'([^']*)')/gi, (fullMatch, attr, quotedValue, dblQuoted, singleQuoted) => {
    const quote = quotedValue[0];
    const value = dblQuoted ?? singleQuoted ?? '';
    return `${attr}=${quote}${rewritePath(value)}${quote}`;
  });

  rewritten = rewritten.replace(/url\((['"]?)([^)'"\s]+)\1\)/gi, (fullMatch, quote, value) => {
    const trimmed = String(value || '').trim();
    if (!trimmed || /^(data:|https?:|\/)/i.test(trimmed)) return fullMatch;
    const rewrittenPath = rewritePath(trimmed);
    return `url(${quote || ''}${rewrittenPath}${quote || ''})`;
  });

  return rewritten;
}

function buildReferenceDocs(db) {
  if (!hasTable(db, 'Docs')) return [];

  const columns = getTableColumns(db, 'Docs');
  const selectColumns = ['id'];
  if (columns.includes('title')) selectColumns.push('title');
  if (columns.includes('name')) selectColumns.push('name');
  if (columns.includes('path')) selectColumns.push('path');

  const rows = dbAll(db, `SELECT ${selectColumns.map(col => `"${col}"`).join(', ')} FROM "Docs" ORDER BY id`);

  return rows.map(row => {
    const salt = String(row.id ?? '1');
    const rawTitle = row.title || row.name || `Document ${row.id}`;
    return {
      id: Number(row.id),
      title: tryDecryptOrReturnRaw(rawTitle, salt),
      path: row.path || '',
    };
  });
}

function flattenReferenceToc(rows) {
  const childrenByParent = new Map();
  const visited = new Set();
  const sortedRows = [...rows].sort((left, right) => {
    const leftOrder = Number(left.displayOrder ?? left.orderId ?? left.id ?? 0);
    const rightOrder = Number(right.displayOrder ?? right.orderId ?? right.id ?? 0);
    if (leftOrder !== rightOrder) return leftOrder - rightOrder;
    return Number(left.id ?? 0) - Number(right.id ?? 0);
  });

  for (const row of sortedRows) {
    const parentKey = row.parentId == null ? 0 : Number(row.parentId);
    if (!childrenByParent.has(parentKey)) childrenByParent.set(parentKey, []);
    childrenByParent.get(parentKey).push(row);
  }

  const result = [];
  const visit = (parentId, level) => {
    const children = childrenByParent.get(parentId) || [];
    for (const child of children) {
      if (visited.has(child.id)) continue;
      visited.add(child.id);
      result.push({
        ...child,
        _level: level,
        _label: child.name || child.title || `Item ${child.id}`,
        _docId: child.docId == null ? null : Number(child.docId),
      });
      visit(Number(child.id), level + 1);
    }
  };

  visit(0, 0);

  for (const row of sortedRows) {
    if (visited.has(row.id)) continue;
    result.push({
      ...row,
      _level: 0,
      _label: row.name || row.title || `Item ${row.id}`,
      _docId: row.docId == null ? null : Number(row.docId),
    });
  }

  return result;
}

function buildReferenceToc(db) {
  if (!hasTable(db, 'TOC')) return [];
  return flattenReferenceToc(dbAll(db, 'SELECT * FROM "TOC" ORDER BY id'));
}

function resolveReferenceDocId(requestedDocId, tocItems, docs) {
  const docIds = new Set(docs.map(doc => Number(doc.id)));
  if (requestedDocId && docIds.has(Number(requestedDocId))) {
    return Number(requestedDocId);
  }

  const tocDoc = tocItems.find(item => item._docId && docIds.has(Number(item._docId)));
  if (tocDoc?._docId) return Number(tocDoc._docId);

  return docs[0] ? Number(docs[0].id) : null;
}

function getReferenceContent(db, docId) {
  const contentTables = ['Docs', 'Content', 'Articles', 'Pages', 'Chapters'];

  for (const tableName of contentTables) {
    if (!hasTable(db, tableName)) continue;

    const row = dbGet(db, `SELECT * FROM "${tableName}" WHERE id = $id`, { $id: docId });
    if (!row) continue;

    const salt = String(row.id ?? docId);
    const contentCandidates = ['doc', 'content', 'mainContent', 'html', 'body', 'text', 'data'];
    let html = '';

    for (const key of contentCandidates) {
      if (typeof row[key] !== 'string' || !row[key].trim()) continue;
      const candidate = tryDecryptOrReturnRaw(row[key], salt);
      if (/<[a-z][\s\S]*>/i.test(candidate) || candidate.trim().startsWith('<')) {
        html = candidate;
        break;
      }
      if (!html) html = candidate;
    }

    if (!html) {
      for (const value of Object.values(row)) {
        if (typeof value !== 'string' || !value.trim()) continue;
        const candidate = tryDecryptOrReturnRaw(value, salt);
        if (/<[a-z][\s\S]*>/i.test(candidate) || candidate.trim().startsWith('<')) {
          html = candidate;
          break;
        }
      }
    }

    const rawTitle = row.title || row.name || `Document ${docId}`;
    return {
      id: Number(row.id ?? docId),
      table: tableName,
      title: tryDecryptOrReturnRaw(rawTitle, salt),
      path: row.path || '',
      html,
    };
  }

  return null;
}

// ----- Stripe -----
const stripeSecretKey = String(process.env.STRIPE_SECRET_KEY || '').trim();
const stripeEnabled = stripeSecretKey.length > 0;
const stripe = stripeEnabled ? require('stripe')(stripeSecretKey) : null;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Stripe webhook needs raw body — must be registered BEFORE express.json()
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripeEnabled || !stripe) {
    return res.status(503).json({ error: 'Payments are not configured on this server' });
  }

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) return res.status(500).json({ error: 'Webhook secret not configured' });

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  try {
    const pool = await getMysqlPool();

    // Log every event
    await pool.execute(
      'INSERT INTO payment_logs (event_type, stripe_event_id, data) VALUES (?, ?, ?)',
      [event.type, event.id, JSON.stringify(event.data.object)]
    );

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = session.metadata?.user_id;
        const planId = session.metadata?.plan_id;
        if (!userId || !planId) break;

        const [[plan]] = await pool.execute('SELECT * FROM subscription_plans WHERE id = ?', [planId]);
        if (!plan) break;

        const subType = plan.name.toLowerCase() === 'lifetime' ? 'premium' : 'premium';
        const expiresDate = plan.duration_days > 0
          ? new Date(Date.now() + plan.duration_days * 86400000).toISOString().split('T')[0]
          : '2099-12-31';

        await pool.execute(
          'UPDATE users SET subscription_type=?, subscription_expires=?, subscription_status=?, stripe_customer_id=COALESCE(stripe_customer_id,?) WHERE id=?',
          [subType, expiresDate, 'active', session.customer || null, userId]
        );

        await pool.execute(
          'INSERT INTO payments (user_id, stripe_payment_id, stripe_subscription_id, plan_id, amount, status, payment_method) VALUES (?,?,?,?,?,?,?)',
          [userId, session.payment_intent || session.id, session.subscription || null, planId, (session.amount_total || 0) / 100, 'completed', 'stripe']
        );

        // Update payment_logs with user_id
        await pool.execute('UPDATE payment_logs SET user_id=? WHERE stripe_event_id=?', [userId, event.id]);

        // Admin notification
        await pool.execute(
          'INSERT INTO admin_notifications (type, title, message, data) VALUES (?,?,?,?)',
          ['payment', 'New Payment Received', `User #${userId} subscribed to ${plan.name} plan`, JSON.stringify({ user_id: userId, plan: plan.name, amount: (session.amount_total || 0) / 100 })]
        );
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        const customerId = invoice.customer;
        if (!customerId) break;
        const [[user]] = await pool.execute('SELECT id FROM users WHERE stripe_customer_id=?', [customerId]);
        if (!user) break;

        // Find their plan from subscription metadata or current plan
        const [[currentPlan]] = await pool.execute(
          'SELECT sp.* FROM subscription_plans sp JOIN payments p ON p.plan_id=sp.id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 1',
          [user.id]
        );
        if (currentPlan && currentPlan.duration_days > 0) {
          const newExpiry = new Date(Date.now() + currentPlan.duration_days * 86400000).toISOString().split('T')[0];
          await pool.execute('UPDATE users SET subscription_expires=?, subscription_status=? WHERE id=?', [newExpiry, 'active', user.id]);
        }

        await pool.execute(
          'INSERT INTO payments (user_id, stripe_payment_id, stripe_subscription_id, plan_id, amount, status, payment_method) VALUES (?,?,?,?,?,?,?)',
          [user.id, invoice.payment_intent, invoice.subscription, currentPlan?.id || 1, (invoice.amount_paid || 0) / 100, 'completed', 'stripe']
        );
        await pool.execute('UPDATE payment_logs SET user_id=? WHERE stripe_event_id=?', [user.id, event.id]);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const customerId = invoice.customer;
        if (!customerId) break;
        const [[user]] = await pool.execute('SELECT id FROM users WHERE stripe_customer_id=?', [customerId]);
        if (!user) break;

        await pool.execute('UPDATE users SET subscription_status=? WHERE id=?', ['past_due', user.id]);
        await pool.execute('UPDATE payment_logs SET user_id=? WHERE stripe_event_id=?', [user.id, event.id]);

        await pool.execute(
          'INSERT INTO admin_notifications (type, title, message, data) VALUES (?,?,?,?)',
          ['payment_failed', 'Payment Failed', `Payment failed for user #${user.id}`, JSON.stringify({ user_id: user.id })]
        );
        break;
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const customerId = sub.customer;
        if (!customerId) break;
        const [[user]] = await pool.execute('SELECT id FROM users WHERE stripe_customer_id=?', [customerId]);
        if (!user) break;

        await pool.execute(
          'UPDATE users SET subscription_type=?, subscription_status=?, auto_renew=0 WHERE id=?',
          ['free', 'cancelled', user.id]
        );
        await pool.execute('UPDATE payment_logs SET user_id=? WHERE stripe_event_id=?', [user.id, event.id]);

        await pool.execute(
          'INSERT INTO admin_notifications (type, title, message, data) VALUES (?,?,?,?)',
          ['subscription_cancelled', 'Subscription Cancelled', `User #${user.id} subscription cancelled`, JSON.stringify({ user_id: user.id })]
        );
        break;
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('Stripe webhook processing error:', err.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// ----- Middleware -----
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function parseCookies(cookieHeader) {
  return String(cookieHeader || '')
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const eqIndex = part.indexOf('=');
      if (eqIndex === -1) return acc;
      const key = decodeURIComponent(part.slice(0, eqIndex).trim());
      const value = decodeURIComponent(part.slice(eqIndex + 1).trim());
      acc[key] = value;
      return acc;
    }, {});
}

function createAuthSignature(payload) {
  return crypto.createHmac('sha256', getAdminSettings().cookieSecret).update(payload).digest('hex');
}

function createAuthToken(username) {
  const payload = Buffer.from(JSON.stringify({ username, expiresAt: Date.now() + AUTH_TTL_MS }), 'utf-8').toString('base64url');
  return `${payload}.${createAuthSignature(payload)}`;
}

function readAuthSession(req) {
  try {
    const token = parseCookies(req.headers.cookie)[AUTH_COOKIE_NAME];
    if (!token) return null;

    const [payload, signature] = token.split('.');
    if (!payload || !signature) return null;
    if (createAuthSignature(payload) !== signature) return null;

    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    if (!parsed?.username || !parsed?.expiresAt || parsed.expiresAt < Date.now()) return null;

    return { username: parsed.username };
  } catch (_) {
    return null;
  }
}

function sanitizeNextPath(nextPath) {
  const candidate = String(nextPath || '').trim();
  if (!candidate.startsWith('/')) return '/dashboard';
  if (candidate.startsWith('//')) return '/dashboard';
  if (candidate.startsWith('/api/')) return '/dashboard';
  return candidate || '/dashboard';
}

function attachAdminSession(req, res, next) {
  req.admin = readAuthSession(req);
  res.locals.isAuthenticated = !!req.admin;
  res.locals.currentAdminUser = req.admin?.username || '';
  next();
}

function requireAdmin(req, res, next) {
  if (req.admin) return next();

  if (req.method === 'GET' || wantsHtmlResponse(req)) {
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || '/dashboard')}`);
  }

  return res.status(401).json({ error: 'Authentication required' });
}

function setAuthCookie(res, username) {
  res.cookie(AUTH_COOKIE_NAME, createAuthToken(username), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: AUTH_TTL_MS,
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });
}

app.use(attachAdminSession);
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ----- Multer -----
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[\\/]/g, '__');
    cb(null, `${Date.now()}-${safeName}`);
  }
});
const upload = multer({
  storage,
  preservePath: true,
  fileFilter: (req, file, cb) => {
    if (file.fieldname === 'packageZip') {
      if (path.extname(file.originalname).toLowerCase() === '.zip') cb(null, true);
      else cb(new Error('Only .zip files are allowed for zip upload'));
      return;
    }

    if (file.fieldname === 'packageFolder') {
      cb(null, true);
      return;
    }

    cb(new Error('Unexpected upload field'));
  },
  limits: {
    fileSize: 500 * 1024 * 1024,
    files: 50000,
  }
});
const uploadContent = upload.fields([
  { name: 'packageZip', maxCount: 1 },
  { name: 'packageFolder', maxCount: 50000 },
]);

// ----- Content dir -----
const CONTENT_DIR = path.join(__dirname, 'content');
if (!fs.existsSync(CONTENT_DIR)) fs.mkdirSync(CONTENT_DIR);

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function normalizeUploadPath(inputPath) {
  return String(inputPath || '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .split('/')
    .filter(Boolean)
    .join('/');
}

function sanitizePackageName(name) {
  const cleaned = String(name || '')
    .trim()
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '-')
    .replace(/\s+/g, ' ')
    .replace(/^\.+|\.+$/g, '');

  return cleaned || `package-${Date.now()}`;
}

function safeJoin(rootDir, relativePath) {
  const rootPath = path.resolve(rootDir);
  const targetPath = path.resolve(rootDir, relativePath);

  if (targetPath !== rootPath && !targetPath.startsWith(`${rootPath}${path.sep}`)) {
    throw new Error('Invalid archive path');
  }

  return targetPath;
}

function detectCommonRoot(paths) {
  const splitPaths = paths
    .map(normalizeUploadPath)
    .filter(Boolean)
    .map(p => p.split('/').filter(Boolean));

  if (splitPaths.length === 0) return '';

  const candidate = splitPaths[0][0];
  const hasNestedPath = splitPaths.some(parts => parts.length > 1);
  if (!candidate || !hasNestedPath) return '';

  return splitPaths.every(parts => parts[0] === candidate) ? candidate : '';
}

function stripRootPrefix(entryPath, rootName) {
  if (!rootName) return entryPath;
  if (entryPath === rootName) return '';
  if (entryPath.startsWith(`${rootName}/`)) return entryPath.slice(rootName.length + 1);
  return entryPath;
}

function cleanupUploadedFiles(files) {
  for (const file of files) {
    if (file?.path && fs.existsSync(file.path)) {
      fs.rmSync(file.path, { force: true });
    }
  }
}

function normalizeUploadedFiles(files) {
  return (files || []).filter(file => file && typeof file.originalname === 'string' && file.originalname.trim());
}

function copyDirContents(sourceDir, destDir) {
  ensureDir(destDir);

  for (const entry of fs.readdirSync(sourceDir)) {
    if (entry === '__MACOSX') continue;

    const sourcePath = path.join(sourceDir, entry);
    const targetPath = path.join(destDir, entry);
    fs.cpSync(sourcePath, targetPath, { recursive: true, force: true });
  }
}

function getVisibleEntries(dirPath) {
  return fs.readdirSync(dirPath, { withFileTypes: true })
    .filter(entry => entry.name !== '__MACOSX' && !entry.name.startsWith('.'));
}

function inspectPackageStructure(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return {
      entries: [],
      directItemCount: 0,
      hasDbFile: false,
      hasGuideConfig: false,
      hasEpubStructure: false,
      hasMediaDir: false,
      hasHtmlFiles: false,
    };
  }

  const entries = getVisibleEntries(dirPath);
  const names = new Set(entries.map(entry => entry.name.toLowerCase()));
  const mediaDirs = new Set(['media-e', 'resources-e', 'images', 'image', 'base']);

  return {
    entries,
    directItemCount: entries.length,
    hasDbFile: entries.some(entry => entry.isFile() && entry.name.toLowerCase().endsWith('.db')),
    hasGuideConfig: names.has('bt_config.txt'),
    hasEpubStructure: names.has('meta-inf') || names.has('oebps'),
    hasMediaDir: entries.some(entry => entry.isDirectory() && mediaDirs.has(entry.name.toLowerCase())),
    hasHtmlFiles: entries.some(entry => entry.isFile() && entry.name.toLowerCase().endsWith('.html')),
  };
}

function isRecognizedPackageStructure(summary) {
  return summary.hasDbFile || summary.hasGuideConfig || (summary.hasEpubStructure && (summary.hasHtmlFiles || summary.hasMediaDir));
}

function hasExtractedContent(dirPath) {
  if (!fs.existsSync(dirPath)) return false;
  return getVisibleEntries(dirPath).length > 0;
}

function resolveExtractedPackage(tempExtractDir, fallbackName) {
  let currentDir = tempExtractDir;
  let packageName = sanitizePackageName(fallbackName);

  for (let depth = 0; depth < 6; depth++) {
    const summary = inspectPackageStructure(currentDir);
    if (isRecognizedPackageStructure(summary)) {
      return { packageName, sourceDir: currentDir };
    }

    const directories = summary.entries.filter(entry => entry.isDirectory());
    if (summary.entries.length === 1 && directories.length === 1) {
      currentDir = path.join(currentDir, directories[0].name);
      packageName = sanitizePackageName(directories[0].name);
      continue;
    }

    break;
  }

  throw new Error('Zip upload did not contain a recognized package structure');
}

function mapZipError(error) {
  const details = `${error?.message || ''}\n${error?.stderr || ''}`;

  if (/End-of-central-directory|unexpected end of file|short read|missing\s+\d+\s+bytes\s+in\s+zipfile/i.test(details)) {
    return new Error('Invalid or incomplete zip file');
  }

  if (error?.code === 'ENOENT') {
    return new Error('No supported zip extraction command is available on this machine');
  }

  return error;
}

async function extractZipToTemp(zipPath, tempExtractDir) {
  const extractionAttempts = process.platform === 'darwin'
    ? [
        () => execFileAsync('ditto', ['-x', '-k', zipPath, tempExtractDir], { maxBuffer: 50 * 1024 * 1024 }),
        () => execFileAsync('unzip', ['-oq', zipPath, '-d', tempExtractDir], { maxBuffer: 50 * 1024 * 1024 }),
      ]
    : [
        () => execFileAsync('unzip', ['-oq', zipPath, '-d', tempExtractDir], { maxBuffer: 50 * 1024 * 1024 }),
      ];

  let lastError = null;

  for (const attempt of extractionAttempts) {
    try {
      await attempt();
      return;
    } catch (error) {
      lastError = error;
      if (hasExtractedContent(tempExtractDir)) {
        return;
      }
    }
  }

  throw mapZipError(lastError);
}

async function extractZipUpload(zipFile) {
  if (!zipFile.size) {
    throw new Error('Uploaded zip file is empty');
  }

  const tempExtractDir = path.join(UPLOADS_DIR, `extract-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  const fallbackName = path.basename(zipFile.originalname, path.extname(zipFile.originalname));

  try {
    ensureDir(tempExtractDir);
    await extractZipToTemp(zipFile.path, tempExtractDir);

    if (!hasExtractedContent(tempExtractDir)) {
      throw new Error('Zip upload did not contain any usable files');
    }

    const resolved = resolveExtractedPackage(tempExtractDir, fallbackName);
    const destDir = path.join(CONTENT_DIR, resolved.packageName);

    if (fs.existsSync(destDir)) fs.rmSync(destDir, { recursive: true, force: true });

    ensureDir(destDir);
    copyDirContents(resolved.sourceDir, destDir);

    if (fs.readdirSync(destDir).length === 0) {
      throw new Error('Zip upload did not contain any usable files');
    }

    return resolved.packageName;
  } catch (error) {
    throw mapZipError(error);
  } finally {
    if (fs.existsSync(tempExtractDir)) {
      fs.rmSync(tempExtractDir, { recursive: true, force: true });
    }
  }
}

function importFolderUpload(files, packageNameOverride) {
  const uploadPaths = files.map(file => normalizeUploadPath(file.originalname)).filter(Boolean);
  if (uploadPaths.length === 0) throw new Error('No folder files uploaded');

  const detectedRoot = detectCommonRoot(uploadPaths);
  const fallbackName = detectedRoot || packageNameOverride || path.basename(uploadPaths[0].split('/')[0] || 'package');
  const packageName = sanitizePackageName(fallbackName);
  const destDir = path.join(CONTENT_DIR, packageName);

  if (fs.existsSync(destDir)) fs.rmSync(destDir, { recursive: true, force: true });
  ensureDir(destDir);

  for (const file of files) {
    const normalizedPath = normalizeUploadPath(file.originalname);
    if (!normalizedPath) continue;

    const relativePath = stripRootPrefix(normalizedPath, detectedRoot);
    if (!relativePath) continue;

    const targetPath = safeJoin(destDir, relativePath);
    ensureDir(path.dirname(targetPath));
    fs.copyFileSync(file.path, targetPath);
  }

  if (!isRecognizedPackageStructure(inspectPackageStructure(destDir))) {
    fs.rmSync(destDir, { recursive: true, force: true });
    throw new Error('Folder upload did not contain a recognized package structure');
  }

  return packageName;
}

function wantsHtmlResponse(req) {
  const accept = String(req.headers.accept || '').toLowerCase();
  return accept.includes('text/html');
}

function buildUploadRedirectUrl(message, isError) {
  const params = new URLSearchParams();
  params.set(isError ? 'uploadError' : 'uploadSuccess', message);
  return `/dashboard?${params.toString()}`;
}

function respondUploadOutcome(req, res, statusCode, message, isError) {
  if (wantsHtmlResponse(req)) {
    return res.redirect(buildUploadRedirectUrl(message, isError));
  }

  if (isError) {
    return res.status(statusCode).json({ error: message });
  }

  return res.json({ ok: true, message });
}

function respondDashboardSettings(req, res, statusCode, message, isError) {
  if (wantsHtmlResponse(req)) {
    const params = new URLSearchParams();
    params.set(isError ? 'settingsError' : 'settingsSuccess', message);
    return res.redirect(`/dashboard?${params.toString()}`);
  }

  if (isError) {
    return res.status(statusCode).json({ error: message });
  }

  return res.json({ ok: true, message });
}

function getPackageInfo(pkgName) {
  const pkgDir = path.join(CONTENT_DIR, pkgName);
  if (!fs.existsSync(pkgDir)) return null;

  const structure = inspectPackageStructure(pkgDir);
  const info = {
    name: pkgName,
    path: pkgDir,
    hasDb: false,
    hasMedia: false,
    hasIcon: false,
    questionCount: 0,
    subjectCount: 0,
    systemCount: 0,
    mediaCount: 0,
    tables: [],
    type: 'other',
    category: 'General',
    directItemCount: structure.directItemCount,
    updatedAt: fs.statSync(pkgDir).mtime.toISOString(),
    isValidPackage: false,
    issue: '',
    statusLabel: 'Needs Attention',
  };
  const files = fs.readdirSync(pkgDir);
  const dbFile = files.find(f => f.endsWith('.db'));

  if (dbFile) {
    info.hasDb = true;
    info.dbFile = dbFile;
    try {
      const db = openDb(path.join(pkgDir, dbFile));
      // Dynamically detect tables
      const tables = dbAll(db, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
      const tableNames = tables.map(t => t.name);
      info.tables = tableNames;

      // Try known MCQ tables, but don't crash if missing
      if (tableNames.includes('Questions')) {
        try { info.questionCount = dbGet(db, 'SELECT COUNT(*) as c FROM Questions').c; } catch (e) {}
      }
      if (tableNames.includes('Subjects')) {
        try { info.subjectCount = dbGet(db, 'SELECT COUNT(*) as c FROM Subjects').c; } catch (e) {}
      }
      if (tableNames.includes('Systems')) {
        try { info.systemCount = dbGet(db, 'SELECT COUNT(*) as c FROM Systems').c; } catch (e) {}
      }
      // For non-MCQ packages, count main content table
      if (!tableNames.includes('Questions')) {
        for (const t of ['Docs', 'Content', 'Articles', 'Pages', 'Chapters']) {
          if (tableNames.includes(t)) {
            try { info.questionCount = dbGet(db, `SELECT COUNT(*) as c FROM "${t}"`).c; } catch (e) {}
            break;
          }
        }
      }
      // Detect package type from tables
      if (tableNames.includes('Questions') && tableNames.includes('Answers')) {
        info.type = 'mcq';
      } else if (tableNames.some(t => ['Docs', 'Content', 'Articles', 'Pages', 'Chapters'].includes(t))) {
        info.type = 'reference';
      } else if (tableNames.some(t => ['Drugs', 'Drug', 'Medications'].includes(t))) {
        info.type = 'drug';
      }

      // Detect category from package name
      const nameLower = pkgName.toLowerCase();
      if (nameLower.includes('uworld') || nameLower.includes('amboss')) info.category = 'USMLE Prep';
      else if (nameLower.includes('nbme') || nameLower.includes('shelf')) info.category = 'Board Exams';
      else if (nameLower.includes('epocrat') || nameLower.includes('lexicomp') || nameLower.includes('drug')) info.category = 'Drug Reference';
      else if (nameLower.includes('skyscape') || nameLower.includes('5minute')) info.category = '5-Minute Consult';
      else if (nameLower.includes('uptodate') || nameLower.includes('dynamed')) info.category = 'Clinical Decision';
      else if (nameLower.includes('mksap')) info.category = 'MKSAP';
      else if (nameLower.includes('harrison') || nameLower.includes('cecil') || nameLower.includes('guyton')) info.category = 'Textbooks';
      else if (nameLower.includes('springer') || nameLower.includes('epub')) info.category = 'eBooks';
      else if (nameLower.includes('amedex') || nameLower.includes('medex') || nameLower.includes('exam')) info.category = 'MCQ Banks';
      else if (nameLower.includes('firstaid') || nameLower.includes('first-aid') || nameLower.includes('kaplan')) info.category = 'USMLE Prep';
      else if (info.type === 'mcq') info.category = 'MCQ Banks';
      else if (info.type === 'reference') info.category = 'References';
      else if (info.type === 'drug') info.category = 'Drug Reference';

      // Get file size
      try {
        const dbStat = fs.statSync(path.join(pkgDir, dbFile));
        info.dbSizeBytes = dbStat.size;
      } catch (e) {}

      db.close();
    } catch (e) { console.error('DB read error:', e.message); }
  }

  // Check for media in media-E/ or Resources-E/ or OEBPS/images/ or images/
  const mediaDirs = ['media-E', 'Resources-E', 'OEBPS/images', 'images', 'Images', 'OEBPS/Images'];
  for (const md of mediaDirs) {
    const mediaDir = path.join(pkgDir, md);
    if (fs.existsSync(mediaDir)) {
      info.hasMedia = true;
      info.mediaDir = md;
      info.mediaCount += fs.readdirSync(mediaDir).length;
    }
  }

  const iconFiles = files.filter(f => /\.(jpg|jpeg|png)$/i.test(f) && !f.startsWith('.'));
  if (iconFiles.length > 0) { info.hasIcon = true; info.iconFile = iconFiles[0]; }

  // BT_config.txt detection (Sanford Guide / BuzzTouch-style content)
  const btConfigPath = path.join(pkgDir, 'BT_config.txt');
  if (fs.existsSync(btConfigPath)) {
    info.hasBtConfig = true;
    if (!dbFile) info.hasDb = false; // override only when there's truly no SQLite DB
    info.type = 'guide';
    info.category = 'Clinical Guides';
    try {
      const config = JSON.parse(fs.readFileSync(btConfigPath, 'utf-8'));
      const screens = config.BT_appConfig.BT_items[0].BT_screens;
      const webViews = screens.filter(s => s.itemType === 'BT_screen_webView');
      info.contentCount = webViews.length;
      info.questionCount = webViews.length;
      // Compute total HTML size
      const htmlFiles = files.filter(f => f.endsWith('.html'));
      info.dbSizeBytes = htmlFiles.reduce((total, f) => {
        try { return total + fs.statSync(path.join(pkgDir, f)).size; } catch { return total; }
      }, 0);
      // Category overrides by name
      const nl = pkgName.toLowerCase();
      if (nl.includes('sanford')) info.category = 'Clinical Guides';
      else if (nl.includes('drug') || nl.includes('pharma')) info.category = 'Drug Reference';
    } catch (e) { console.error('BT_config parse error for ' + pkgName + ':', e.message); }
  }

  info.isValidPackage = isRecognizedPackageStructure(structure);
  info.statusLabel = info.isValidPackage ? 'Ready' : 'Needs Attention';
  info.issue = info.isValidPackage ? '' : 'Missing database or supported guide/package structure';

  return info;
}

function loadDashboardEntries() {
  return fs.readdirSync(CONTENT_DIR)
    .filter(f => fs.statSync(path.join(CONTENT_DIR, f)).isDirectory())
    .map(getPackageInfo)
    .filter(Boolean)
    .sort((a, b) => {
      if (a.isValidPackage !== b.isValidPackage) return a.isValidPackage ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
}

function loadDashboardPackages() {
  return loadDashboardEntries().filter(pkg => pkg.isValidPackage);
}

function formatBytes(bytes) {
  const size = Number(bytes || 0);
  if (!size) return '0 B';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function countStaleUploads() {
  let staleCount = 0;
  if (!fs.existsSync(UPLOADS_DIR)) return staleCount;

  try {
    const files = fs.readdirSync(UPLOADS_DIR);
    for (const fileName of files) {
      try {
        const stat = fs.statSync(path.join(UPLOADS_DIR, fileName));
        if (stat.isFile() && stat.size === 0) staleCount++;
      } catch (_) {}
    }
  } catch (_) {}

  return staleCount;
}

function parsePositiveInt(value, fallbackValue) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallbackValue;
}

function normalizeDashboardQuery(query) {
  const allowedPageSizes = new Set([10, 25, 50, 100]);
  const pageSize = parsePositiveInt(query.pageSize, 10);

  return {
    q: String(query.q || '').trim(),
    type: String(query.type || '').trim().toLowerCase(),
    category: String(query.category || '').trim(),
    page: parsePositiveInt(query.page, 1),
    invalidPage: parsePositiveInt(query.invalidPage, 1),
    pageSize: allowedPageSizes.has(pageSize) ? pageSize : 10,
  };
}

function matchesDashboardSearch(entry, searchTerm) {
  if (!searchTerm) return true;

  const haystack = [
    entry.name,
    entry.type,
    entry.category,
    entry.statusLabel,
    entry.issue,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return haystack.includes(searchTerm);
}

function filterDashboardEntries(entries, filters) {
  const searchTerm = filters.q.toLowerCase();

  return entries.filter(entry => {
    if (!matchesDashboardSearch(entry, searchTerm)) return false;
    if (filters.type && entry.type !== filters.type) return false;
    if (filters.category && entry.category !== filters.category) return false;
    return true;
  });
}

function paginateItems(items, page, pageSize) {
  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const currentPage = Math.min(Math.max(page, 1), totalPages);
  const startIndex = totalItems === 0 ? 0 : (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);

  return {
    items: items.slice(startIndex, endIndex),
    totalItems,
    totalPages,
    page: currentPage,
    pageSize,
    startItem: totalItems === 0 ? 0 : startIndex + 1,
    endItem: endIndex,
  };
}

function buildDashboardHref(currentFilters, updates = {}) {
  const merged = { ...currentFilters, ...updates };
  const params = new URLSearchParams();

  if (merged.q) params.set('q', merged.q);
  if (merged.type) params.set('type', merged.type);
  if (merged.category) params.set('category', merged.category);
  if (merged.page && merged.page !== 1) params.set('page', String(merged.page));
  if (merged.invalidPage && merged.invalidPage !== 1) params.set('invalidPage', String(merged.invalidPage));
  if (merged.pageSize && merged.pageSize !== 10) params.set('pageSize', String(merged.pageSize));

  const queryString = params.toString();
  return queryString ? `/dashboard?${queryString}` : '/dashboard';
}

function buildDashboardModel(query = {}) {
  const filters = normalizeDashboardQuery(query);
  const adminSettings = getAdminSettings();
  const entries = loadDashboardEntries();
  const packages = entries.filter(entry => entry.isValidPackage);
  const invalidPackages = entries.filter(entry => !entry.isValidPackage);

  const decorateEntry = entry => ({
    ...entry,
    sizeLabel: formatBytes(entry.dbSizeBytes),
    updatedLabel: new Date(entry.updatedAt).toLocaleString(),
  });

  const decoratedPackages = packages.map(decorateEntry);
  const decoratedInvalidPackages = invalidPackages.map(decorateEntry);
  const filteredPackages = filterDashboardEntries(decoratedPackages, filters);
  const filteredInvalidPackages = filterDashboardEntries(decoratedInvalidPackages, filters);
  const packagesPage = paginateItems(filteredPackages, filters.page, filters.pageSize);
  const invalidPackagesPage = paginateItems(filteredInvalidPackages, filters.invalidPage, filters.pageSize);
  const categories = [...new Set(decoratedPackages.map(entry => entry.category).filter(Boolean))].sort((left, right) => left.localeCompare(right));
  const types = [...new Set(decoratedPackages.map(entry => entry.type).filter(Boolean))].sort((left, right) => left.localeCompare(right));

  return {
    packages: packagesPage.items,
    invalidPackages: invalidPackagesPage.items,
    packagesPage,
    invalidPackagesPage,
    dashboardFilters: filters,
    hasActiveFilters: Boolean(filters.q || filters.type || filters.category),
    authSettings: {
      username: adminSettings.username,
      updatedAtLabel: new Date(adminSettings.updatedAt).toLocaleString(),
      usesDefaultPassword: usesDefaultAdminPassword(),
    },
    filterOptions: {
      categories,
      types,
      pageSizes: [10, 25, 50, 100],
    },
    staleCount: countStaleUploads(),
    stats: {
      totalEntries: entries.length,
      readyPackages: packages.length,
      invalidPackages: invalidPackages.length,
      totalQuestions: packages.reduce((sum, entry) => sum + Number(entry.questionCount || 0), 0),
      totalMedia: packages.reduce((sum, entry) => sum + Number(entry.mediaCount || 0), 0),
    },
  };
}

function renderDashboard(req, res, overrides = {}) {
  const dashboardModel = buildDashboardModel(req.query);
  res.render('dashboard', {
    ...dashboardModel,
    buildDashboardHref: updates => buildDashboardHref(dashboardModel.dashboardFilters, updates),
    uploadError: overrides.uploadError ?? req.query.uploadError ?? '',
    uploadSuccess: overrides.uploadSuccess ?? req.query.uploadSuccess ?? '',
    settingsError: overrides.settingsError ?? req.query.settingsError ?? '',
    settingsSuccess: overrides.settingsSuccess ?? req.query.settingsSuccess ?? '',
  });
}

// ----- Admin routes -----
app.get('/', (req, res) => {
  res.redirect(req.admin ? '/dashboard' : '/login');
});

app.get('/upload', (req, res) => {
  res.redirect(req.admin ? '/dashboard' : '/login?next=%2Fdashboard');
});

app.get('/login', (req, res) => {
  const nextPath = sanitizeNextPath(req.query.next);
  if (req.admin) {
    return res.redirect(nextPath);
  }

  res.render('login', {
    error: String(req.query.error || ''),
    nextPath,
    username: String(req.query.username || ''),
  });
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const nextPath = sanitizeNextPath(req.body.next || req.query.next);
  const adminSettings = getAdminSettings();

  if (username !== adminSettings.username || !verifyAdminPassword(password, adminSettings.passwordSalt, adminSettings.passwordHash)) {
    if (wantsHtmlResponse(req)) {
      return res.status(401).render('login', {
        error: 'Invalid username or password',
        nextPath,
        username,
      });
    }

    return res.status(401).json({ error: 'Invalid username or password' });
  }

  setAuthCookie(res, username);

  if (wantsHtmlResponse(req)) {
    return res.redirect(nextPath);
  }

  return res.json({ ok: true, next: nextPath });
});

app.post('/logout', (req, res) => {
  clearAuthCookie(res);

  if (wantsHtmlResponse(req)) {
    return res.redirect('/login');
  }

  return res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════
// ─── User Web Auth (Signup / User Dashboard / Plans) ───
// ═══════════════════════════════════════════════════════════

// Middleware: verify user web session (cookie-based for web, bearer for API)
async function requireUserAuth(req, res, next) {
  // Try bearer token first (API calls)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return requireAppAuth(req, res, next);
  }
  // Try user session cookie
  const cookies = parseCookies(req.headers.cookie);
  const userToken = cookies['imd_user_token'];
  if (!userToken) {
    if (wantsHtmlResponse(req)) return res.redirect('/signup?error=Please+log+in');
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT s.id AS session_id, s.user_id, u.username, u.email, u.full_name, u.subscription_type, u.subscription_expires, u.subscription_status, u.auto_renew, u.stripe_customer_id FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.is_active=1 AND s.expires_at > NOW()',
      [userToken]
    );
    if (rows.length === 0) {
      res.clearCookie('imd_user_token', { path: '/' });
      if (wantsHtmlResponse(req)) return res.redirect('/signup?error=Session+expired');
      return res.status(401).json({ error: 'Session expired' });
    }
    req.appUser = rows[0];
    next();
  } catch (err) {
    console.error('User auth error:', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

function hasActivePaidSubscription(user) {
  const subscriptionType = String(user?.subscription_type || 'free').toLowerCase();
  if (!subscriptionType || subscriptionType === 'free') return false;

  const subscriptionStatus = String(user?.subscription_status || 'active').toLowerCase();
  if (subscriptionStatus === 'expired') return false;

  if (user?.subscription_expires) {
    const expiresAt = new Date(user.subscription_expires);
    if (!Number.isNaN(expiresAt.getTime()) && expiresAt < new Date()) {
      return false;
    }
  }

  return true;
}

function requirePaidUser(req, res, next) {
  if (hasActivePaidSubscription(req.appUser)) return next();

  if (wantsHtmlResponse(req)) {
    return res.redirect('/select-plan?error=Please+complete+subscription+payment+to+continue');
  }

  return res.status(402).json({
    error: 'Active paid subscription required. Please sign up and pay on the web portal.',
    requires_subscription: true,
    signup_url: `${BASE_URL}/signup`,
  });
}

// GET /signup
app.get('/signup', (req, res) => {
  res.render('signup', {
    error: req.query.error || '',
    success: req.query.success || '',
  });
});

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  if (!wantsHtmlResponse(req)) {
    return res.status(403).json({
      error: 'Signup is only available on the web portal. Please complete subscription payment before login.',
      signup_url: `${BASE_URL}/signup`,
    });
  }

  const { full_name, email, username, password, confirm_password, device_id } = req.body || {};

  // Validation
  if (!username || !password || !email) {
    const err = 'Username, email, and password are required';
    if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
    return res.status(400).json({ error: err });
  }
  if (String(username).trim().length < 3) {
    const err = 'Username must be at least 3 characters';
    if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
    return res.status(400).json({ error: err });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())) {
    const err = 'Please enter a valid email address';
    if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
    return res.status(400).json({ error: err });
  }
  if (String(password).length < 8) {
    const err = 'Password must be at least 8 characters';
    if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
    return res.status(400).json({ error: err });
  }
  if (!/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    const err = 'Password must include at least 1 uppercase letter and 1 number';
    if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
    return res.status(400).json({ error: err });
  }
  if (confirm_password !== undefined && password !== confirm_password) {
    const err = 'Passwords do not match';
    if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
    return res.status(400).json({ error: err });
  }

  try {
    const pool = await getMysqlPool();
    const cleanUsername = String(username).trim().toLowerCase();
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanName = String(full_name || '').trim();

    // Check uniqueness
    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE username=? OR email=?',
      [cleanUsername, cleanEmail]
    );
    if (existing.length > 0) {
      const err = 'Username or email already exists';
      if (wantsHtmlResponse(req)) return res.render('signup', { error: err, success: '' });
      return res.status(409).json({ error: err });
    }

    // Hash password
    const { salt, hash } = hashUserPassword(password);

    // Insert user
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, full_name, password_salt, password_hash, subscription_type, subscription_status) VALUES (?,?,?,?,?,?,?)',
      [cleanUsername, cleanEmail, cleanName || null, salt, hash, 'free', 'active']
    );
    const userId = result.insertId;

    // Create session
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await pool.execute(
      'INSERT INTO sessions (user_id, token, device_id, expires_at, is_active) VALUES (?,?,?,?,1)',
      [userId, token, device_id || null, expiresAt]
    );

    // Admin notification
    await pool.execute(
      'INSERT INTO admin_notifications (type, title, message, data) VALUES (?,?,?,?)',
      ['new_user', 'New User Signup', `${cleanUsername} (${cleanEmail}) registered`, JSON.stringify({ user_id: userId, username: cleanUsername })]
    );

    // For web requests, set cookie and redirect to plan selection
    if (wantsHtmlResponse(req)) {
      res.cookie('imd_user_token', token, {
        httpOnly: true, sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000, path: '/',
      });
      return res.redirect('/select-plan');
    }

    // For API requests, return token
    res.status(201).json({
      token,
      expires_at: expiresAt.toISOString(),
      user: { id: userId, username: cleanUsername, email: cleanEmail, full_name: cleanName, subscription_type: 'free' },
    });
  } catch (err) {
    console.error('Registration error:', err.message);
    if (wantsHtmlResponse(req)) return res.render('signup', { error: 'Registration failed. Please try again.', success: '' });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /signup (web form)
app.post('/signup', (req, res, next) => {
  // Delegate to the API handler
  req.headers['accept'] = 'text/html';
  app.handle(Object.assign(req, { url: '/api/auth/register', method: 'POST' }), res, next);
});

// GET /select-plan
app.get('/select-plan', async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [plans] = await pool.execute('SELECT * FROM subscription_plans WHERE is_active=1 AND price > 0 ORDER BY price ASC');
    // Parse features JSON
    const plansWithFeatures = plans.map(p => ({
      ...p,
      features: (() => { try { return JSON.parse(p.features || '[]'); } catch { return []; } })(),
    }));

    // Try to resolve logged-in user from cookie
    let user = null;
    const cookies = parseCookies(req.headers.cookie);
    const userToken = cookies['imd_user_token'];
    if (userToken) {
      const [rows] = await pool.execute(
        'SELECT s.user_id, u.username, u.full_name FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.is_active=1 AND s.expires_at > NOW()',
        [userToken]
      );
      if (rows.length > 0) user = rows[0];
    }

    res.render('select-plan', {
      plans: plansWithFeatures,
      stripeKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
      error: req.query.error || '',
      user,
    });
  } catch (err) {
    console.error('Select plan error:', err.message);
    res.render('select-plan', { plans: [], stripeKey: '', error: '', user: null });
  }
});

// GET /user/dashboard
app.get('/user/dashboard', requireUserAuth, requirePaidUser, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const u = req.appUser;

    // Get payment history
    const [payments] = await pool.execute(
      'SELECT p.*, sp.name AS plan_name FROM payments p LEFT JOIN subscription_plans sp ON p.plan_id=sp.id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 20',
      [u.user_id]
    );

    // Get current plan info
    const [plans] = await pool.execute('SELECT * FROM subscription_plans WHERE is_active=1 ORDER BY price ASC');

    let daysRemaining = 0;
    if (u.subscription_expires) {
      daysRemaining = Math.max(0, Math.ceil((new Date(u.subscription_expires) - Date.now()) / 86400000));
    }

    res.render('user-dashboard', {
      user: u,
      payments,
      plans,
      daysRemaining,
      stripeKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
    });
  } catch (err) {
    console.error('User dashboard error:', err.message);
    res.redirect('/signup?error=Something+went+wrong');
  }
});

// GET /payment/success
app.get('/payment/success', (req, res) => {
  res.render('payment-success', { session_id: req.query.session_id || '' });
});

// GET /payment/cancel
app.get('/payment/cancel', (req, res) => {
  res.render('payment-cancel');
});

// POST /user/logout
app.post('/user/logout', async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const userToken = cookies['imd_user_token'];
  if (userToken) {
    try {
      const pool = await getMysqlPool();
      await pool.execute('UPDATE sessions SET is_active=0 WHERE token=?', [userToken]);
    } catch (_) {}
  }
  res.clearCookie('imd_user_token', { path: '/' });
  res.redirect('/signup');
});

// ═══════════════════════════════════════════════════════════
// ─── Stripe Payment Endpoints ───
// ═══════════════════════════════════════════════════════════

// POST /api/payments/create-checkout-session
app.post('/api/payments/create-checkout-session', requireUserAuth, async (req, res) => {
  if (!stripeEnabled || !stripe) {
    return res.status(503).json({ error: 'Payments are not configured on this server' });
  }

  const { plan_id } = req.body || {};
  if (!plan_id) return res.status(400).json({ error: 'plan_id required' });

  try {
    const pool = await getMysqlPool();
    const [[plan]] = await pool.execute('SELECT * FROM subscription_plans WHERE id=? AND is_active=1', [plan_id]);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    if (plan.price <= 0) return res.status(400).json({ error: 'Cannot checkout free plan' });
    if (!plan.stripe_price_id) return res.status(400).json({ error: 'Stripe price not configured for this plan' });

    const userId = req.appUser.user_id;
    const userEmail = req.appUser.email;

    // Get or create Stripe customer
    let customerId = req.appUser.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: userEmail,
        metadata: { user_id: String(userId) },
      });
      customerId = customer.id;
      await pool.execute('UPDATE users SET stripe_customer_id=? WHERE id=?', [customerId, userId]);
    }

    const isLifetime = plan.name.toLowerCase() === 'lifetime';
    const sessionParams = {
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: plan.stripe_price_id, quantity: 1 }],
      mode: isLifetime ? 'payment' : 'subscription',
      success_url: `${BASE_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${BASE_URL}/payment/cancel`,
      metadata: { user_id: String(userId), plan_id: String(plan.id) },
    };

    if (!isLifetime) {
      sessionParams.subscription_data = {
        metadata: { user_id: String(userId), plan_id: String(plan.id) },
      };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);
    res.json({ url: session.url, session_id: session.id });
  } catch (err) {
    console.error('Checkout session error:', err.message);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// POST /api/payments/create-mobile-checkout (for in-app WebView)
app.post('/api/payments/create-mobile-checkout', requireAppAuth, async (req, res) => {
  if (!stripeEnabled || !stripe) {
    return res.status(503).json({ error: 'Payments are not configured on this server' });
  }

  const { plan_id } = req.body || {};
  if (!plan_id) return res.status(400).json({ error: 'plan_id required' });

  try {
    const pool = await getMysqlPool();
    const [[plan]] = await pool.execute('SELECT * FROM subscription_plans WHERE id=? AND is_active=1', [plan_id]);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });
    if (plan.price <= 0) return res.status(400).json({ error: 'Cannot checkout free plan' });
    if (!plan.stripe_price_id) return res.status(400).json({ error: 'Stripe price not configured for this plan' });

    const userId = req.appUser.user_id;
    const [userRows] = await pool.execute('SELECT email, stripe_customer_id FROM users WHERE id=?', [userId]);
    const user = userRows[0];

    let customerId = user?.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user?.email || '',
        metadata: { user_id: String(userId) },
      });
      customerId = customer.id;
      await pool.execute('UPDATE users SET stripe_customer_id=? WHERE id=?', [customerId, userId]);
    }

    const isLifetime = plan.name.toLowerCase() === 'lifetime';
    const sessionParams = {
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: plan.stripe_price_id, quantity: 1 }],
      mode: isLifetime ? 'payment' : 'subscription',
      success_url: `${BASE_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}&mobile=1`,
      cancel_url: `${BASE_URL}/payment/cancel?mobile=1`,
      metadata: { user_id: String(userId), plan_id: String(plan.id) },
    };

    if (!isLifetime) {
      sessionParams.subscription_data = {
        metadata: { user_id: String(userId), plan_id: String(plan.id) },
      };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);
    res.json({ url: session.url, session_id: session.id });
  } catch (err) {
    console.error('Mobile checkout error:', err.message);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// GET /api/payments/history
app.get('/api/payments/history', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [payments] = await pool.execute(
      'SELECT p.*, sp.name AS plan_name FROM payments p LEFT JOIN subscription_plans sp ON p.plan_id=sp.id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 50',
      [req.appUser.user_id]
    );
    res.json(payments);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════
// ─── Subscription Management API ───
// ═══════════════════════════════════════════════════════════

// GET /api/subscription/status
app.get('/api/subscription/status', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [[user]] = await pool.execute(
      'SELECT subscription_type, subscription_expires, subscription_status, auto_renew, stripe_customer_id FROM users WHERE id=?',
      [req.appUser.user_id]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    let daysRemaining = 0;
    if (user.subscription_expires) {
      daysRemaining = Math.max(0, Math.ceil((new Date(user.subscription_expires) - Date.now()) / 86400000));
    }

    // Get current plan name
    const [[latestPayment]] = await pool.execute(
      'SELECT sp.name AS plan_name, sp.price FROM payments p JOIN subscription_plans sp ON p.plan_id=sp.id WHERE p.user_id=? AND p.status=? ORDER BY p.created_at DESC LIMIT 1',
      [req.appUser.user_id, 'completed']
    );

    res.json({
      subscription_type: user.subscription_type,
      subscription_expires: user.subscription_expires,
      subscription_status: user.subscription_status,
      auto_renew: !!user.auto_renew,
      days_remaining: daysRemaining,
      plan_name: latestPayment?.plan_name || (user.subscription_type === 'free' ? 'Free' : 'Premium'),
      plan_price: latestPayment?.price || 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/subscription/plans
app.get('/api/subscription/plans', async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [plans] = await pool.execute('SELECT id, name, description, duration_days, price, access_level, features FROM subscription_plans WHERE is_active=1 ORDER BY price ASC');
    const parsed = plans.map(p => ({
      ...p,
      features: (() => { try { return JSON.parse(p.features || '[]'); } catch { return []; } })(),
    }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/subscription/toggle-auto-renew
app.post('/api/subscription/toggle-auto-renew', requireUserAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [[user]] = await pool.execute('SELECT auto_renew, stripe_customer_id FROM users WHERE id=?', [req.appUser.user_id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newAutoRenew = !user.auto_renew;

    // If user has a Stripe subscription, update it
    if (user.stripe_customer_id && process.env.STRIPE_SECRET_KEY) {
      try {
        const subscriptions = await stripe.subscriptions.list({ customer: user.stripe_customer_id, status: 'active', limit: 1 });
        if (subscriptions.data.length > 0) {
          await stripe.subscriptions.update(subscriptions.data[0].id, {
            cancel_at_period_end: !newAutoRenew,
          });
        }
      } catch (stripeErr) {
        console.error('Stripe auto-renew toggle error:', stripeErr.message);
      }
    }

    await pool.execute('UPDATE users SET auto_renew=? WHERE id=?', [newAutoRenew ? 1 : 0, req.appUser.user_id]);
    res.json({ auto_renew: newAutoRenew });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/subscription/change-plan
app.post('/api/subscription/change-plan', requireAppAuth, async (req, res) => {
  const { plan_id } = req.body || {};
  if (!plan_id) return res.status(400).json({ error: 'plan_id required' });

  try {
    const pool = await getMysqlPool();
    const [[plan]] = await pool.execute('SELECT * FROM subscription_plans WHERE id=? AND is_active=1', [plan_id]);
    if (!plan) return res.status(404).json({ error: 'Plan not found' });

    // For paid plans, redirect to checkout
    if (plan.price > 0) {
      return res.json({ action: 'checkout', plan_id: plan.id });
    }

    // Downgrade to free
    await pool.execute(
      'UPDATE users SET subscription_type=?, subscription_status=? WHERE id=?',
      ['free', 'active', req.appUser.user_id]
    );
    res.json({ success: true, subscription_type: 'free' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/subscription/cancel
app.post('/api/subscription/cancel', requireUserAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [[user]] = await pool.execute('SELECT stripe_customer_id, subscription_expires FROM users WHERE id=?', [req.appUser.user_id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Cancel Stripe subscription at period end
    if (user.stripe_customer_id && process.env.STRIPE_SECRET_KEY) {
      try {
        const subscriptions = await stripe.subscriptions.list({ customer: user.stripe_customer_id, status: 'active', limit: 1 });
        if (subscriptions.data.length > 0) {
          await stripe.subscriptions.update(subscriptions.data[0].id, { cancel_at_period_end: true });
        }
      } catch (stripeErr) {
        console.error('Stripe cancel error:', stripeErr.message);
      }
    }

    await pool.execute('UPDATE users SET subscription_status=?, auto_renew=0 WHERE id=?', ['cancelled', req.appUser.user_id]);

    let daysRemaining = 0;
    if (user.subscription_expires) {
      daysRemaining = Math.max(0, Math.ceil((new Date(user.subscription_expires) - Date.now()) / 86400000));
    }

    res.json({ success: true, days_remaining: daysRemaining, message: `Your subscription will remain active until ${user.subscription_expires || 'the end of your billing period'}.` });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/subscription/history
app.get('/api/subscription/history', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [payments] = await pool.execute(
      'SELECT p.amount, p.currency, p.status, p.payment_method, p.created_at, sp.name AS plan_name FROM payments p LEFT JOIN subscription_plans sp ON p.plan_id=sp.id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 50',
      [req.appUser.user_id]
    );
    res.json(payments);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/auth/account — update profile
app.put('/api/auth/account', requireUserAuth, async (req, res) => {
  const { full_name, email } = req.body || {};
  try {
    const pool = await getMysqlPool();
    const updates = [];
    const params = [];

    if (full_name !== undefined) { updates.push('full_name=?'); params.push(String(full_name).trim()); }
    if (email !== undefined) {
      const cleanEmail = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      // Check uniqueness
      const [existing] = await pool.execute('SELECT id FROM users WHERE email=? AND id!=?', [cleanEmail, req.appUser.user_id]);
      if (existing.length > 0) return res.status(409).json({ error: 'Email already in use' });
      updates.push('email=?');
      params.push(cleanEmail);
    }

    if (updates.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    params.push(req.appUser.user_id);
    await pool.execute(`UPDATE users SET ${updates.join(', ')} WHERE id=?`, params);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/auth/change-password
app.put('/api/auth/change-password', requireUserAuth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) return res.status(400).json({ error: 'Current and new password required' });
  if (String(new_password).length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

  try {
    const pool = await getMysqlPool();
    const [[user]] = await pool.execute('SELECT password_salt, password_hash FROM users WHERE id=?', [req.appUser.user_id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!verifyUserPassword(current_password, user.password_salt, user.password_hash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const { salt, hash } = hashUserPassword(new_password);
    await pool.execute('UPDATE users SET password_salt=?, password_hash=? WHERE id=?', [salt, hash, req.appUser.user_id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/settings/credentials', requireAdmin, (req, res) => {
  const username = String(req.body.username || '').trim();
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  const confirmPassword = String(req.body.confirmPassword || '');
  const cookieSecret = String(req.body.cookieSecret || '').trim();
  const currentSettings = getAdminSettings();

  if (!username) {
    return respondDashboardSettings(req, res, 400, 'Username is required', true);
  }

  if (!verifyAdminPassword(currentPassword, currentSettings.passwordSalt, currentSettings.passwordHash)) {
    return respondDashboardSettings(req, res, 400, 'Current password is incorrect', true);
  }

  if (newPassword && newPassword.length < 6) {
    return respondDashboardSettings(req, res, 400, 'New password must be at least 6 characters', true);
  }

  if (newPassword !== confirmPassword) {
    return respondDashboardSettings(req, res, 400, 'New password and confirmation do not match', true);
  }

  if (cookieSecret && cookieSecret.length < 16) {
    return respondDashboardSettings(req, res, 400, 'Cookie secret must be at least 16 characters', true);
  }

  const updatedSettings = updateAdminSettings({
    username,
    password: newPassword || undefined,
    cookieSecret: cookieSecret || undefined,
  });

  clearAuthCookie(res);
  setAuthCookie(res, updatedSettings.username);

  return respondDashboardSettings(req, res, 200, 'Admin credentials updated successfully', false);
});

app.get('/dashboard', requireAdmin, (req, res) => {
  renderDashboard(req, res);
});

app.get('/admin/manage', requireAdmin, (req, res) => {
  res.render('admin-manage');
});

app.post('/cleanup-uploads', requireAdmin, (req, res) => {
  let removed = 0;
  if (fs.existsSync(UPLOADS_DIR)) {
    try {
      const files = fs.readdirSync(UPLOADS_DIR);
      for (const f of files) {
        const fp = path.join(UPLOADS_DIR, f);
        try {
          const stat = fs.statSync(fp);
          if (stat.isFile() && stat.size === 0) {
            fs.unlinkSync(fp);
            removed++;
          }
        } catch (_) {}
      }
    } catch (_) {}
  }
  return respondUploadOutcome(req, res, 200, `Cleaned ${removed} stale zero-byte files`, false);
});

app.get('/package/:name', requireAdmin, (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).send('Package not found');

  const questions = [];
  const subjects = [];
  const systems = [];
  const referenceDocs = [];
  const referenceToc = [];
  const subjectFilter = req.query.subject || '';
  const systemFilter = req.query.system || '';
  const requestedDocId = parseInt(req.query.doc, 10);

  let page = parseInt(req.query.page, 10) || 1;
  let totalPages = 0;
  let total = 0;
  let selectedDocId = Number.isFinite(requestedDocId) ? requestedDocId : null;
  let referenceContentHtml = '';
  let referenceContentTitle = '';
  let referenceContentTable = '';

  if (pkg.hasDb) {
    const db = openDb(path.join(pkg.path, pkg.dbFile));

    try {
      if (pkg.type === 'mcq' && hasTable(db, 'Questions')) {
        if (hasTable(db, 'Subjects')) {
          subjects.push(...dbAll(db, 'SELECT * FROM Subjects ORDER BY name'));
        }
        if (hasTable(db, 'Systems')) {
          systems.push(...dbAll(db, 'SELECT * FROM Systems ORDER BY name'));
        }

        const limit = 20;
        const offset = (page - 1) * limit;
        const where = [];
        const params = {};

        if (subjectFilter) { where.push('q.subId = $subject'); params.$subject = parseInt(subjectFilter, 10); }
        if (systemFilter) { where.push('q.sysId = $system'); params.$system = parseInt(systemFilter, 10); }

        const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
        total = dbGet(db, `SELECT COUNT(*) as c FROM Questions q ${wc}`, Object.keys(params).length ? params : undefined).c;

        const subjectJoin = hasTable(db, 'Subjects') ? 'LEFT JOIN Subjects s ON q.subId = s.id' : '';
        const systemJoin = hasTable(db, 'Systems') ? 'LEFT JOIN Systems sy ON q.sysId = sy.id' : '';
        const selectFields = [
          'q.*',
          hasTable(db, 'Subjects') ? 's.name as subjectName' : 'NULL as subjectName',
          hasTable(db, 'Systems') ? 'sy.name as systemName' : 'NULL as systemName',
        ].join(', ');

        const rows = dbAll(
          db,
          `SELECT ${selectFields} FROM Questions q ${subjectJoin} ${systemJoin} ${wc} ORDER BY q.id LIMIT $limit OFFSET $offset`,
          { ...params, $limit: limit, $offset: offset },
        );

        questions.push(...rows.map(row => {
          const salt = String(row.id);
          let dec = '';
          let decE = '';
          try { dec = decryptText(row.question, salt); } catch (e) { dec = '[Decryption error]'; }
          try { if (row.explanation) decE = decryptText(row.explanation, salt); } catch (e) { decE = ''; }

          const answers = hasTable(db, 'Answers')
            ? dbAll(db, 'SELECT * FROM Answers WHERE qId = $qid ORDER BY answerId', { $qid: row.id }).map(a => {
                let decA = '';
                try { decA = decryptText(a.answerText, salt); } catch (e) { decA = ''; }
                return { answerId: a.answerId, answerText: decA, isCorrect: a.answerId === row.corrAns };
              })
            : [];

          return {
            ...row,
            decryptedQuestion: rewritePackageHtml(dec, pkg.name, ''),
            explanation: rewritePackageHtml(decE, pkg.name, ''),
            answers,
          };
        }));

        totalPages = Math.ceil(total / limit);
      } else if (pkg.type === 'reference' && hasTable(db, 'Docs')) {
        referenceDocs.push(...buildReferenceDocs(db));
        referenceToc.push(...buildReferenceToc(db));
        total = referenceDocs.length;
        totalPages = referenceDocs.length > 0 ? 1 : 0;
        page = 1;

        selectedDocId = resolveReferenceDocId(selectedDocId, referenceToc, referenceDocs);
        if (selectedDocId != null) {
          const content = getReferenceContent(db, selectedDocId);
          const docMeta = referenceDocs.find(doc => Number(doc.id) === Number(selectedDocId));
          const docPath = content?.path || docMeta?.path || '';
          referenceContentTitle = content?.title || docMeta?.title || `Document ${selectedDocId}`;
          referenceContentTable = content?.table || 'Docs';
          referenceContentHtml = rewritePackageHtml(content?.html || '', pkg.name, docPath);
        }
      }
    } finally {
      db.close();
    }
  }

  res.render('package', {
    pkg,
    questions,
    subjects,
    systems,
    page,
    totalPages,
    total,
    subjectFilter,
    systemFilter,
    search: '',
    viewMode: pkg.type === 'reference' ? 'reference' : (pkg.type === 'guide' ? 'guide' : 'mcq'),
    referenceDocs,
    referenceToc,
    selectedDocId,
    referenceContentHtml,
    referenceContentTitle,
    referenceContentTable,
  });
});

app.post('/upload', requireAdmin, (req, res, next) => {
  uploadContent(req, res, err => {
    if (err) return respondUploadOutcome(req, res, 400, err.message, true);
    next();
  });
}, async (req, res) => {
  const zipFiles = normalizeUploadedFiles(req.files?.packageZip);
  const folderFiles = normalizeUploadedFiles(req.files?.packageFolder);
  const zipFile = zipFiles[0] || null;
  const allUploadedFiles = [zipFile, ...folderFiles].filter(Boolean);

  if (zipFiles.length > 1) {
    cleanupUploadedFiles(allUploadedFiles);
    return respondUploadOutcome(req, res, 400, 'Upload only one zip file at a time', true);
  }

  if (!zipFile && folderFiles.length === 0) {
    cleanupUploadedFiles(allUploadedFiles);
    return respondUploadOutcome(req, res, 400, 'Upload a zip file or choose a folder', true);
  }

  if (zipFile && folderFiles.length > 0) {
    cleanupUploadedFiles(allUploadedFiles);
    return respondUploadOutcome(req, res, 400, 'Choose either a zip file or a folder upload, not both', true);
  }

  try {
    let packageName = '';

    if (zipFile) {
      packageName = await extractZipUpload(zipFile);
    } else {
      packageName = importFolderUpload(folderFiles, req.body.packageName);
    }

    cleanupUploadedFiles(allUploadedFiles);
    return respondUploadOutcome(req, res, 200, `Uploaded ${packageName} successfully`, false);
  } catch (e) {
    cleanupUploadedFiles(allUploadedFiles);
    console.error('Upload error:', e);
    return respondUploadOutcome(req, res, 500, e.message, true);
  }
});

app.post('/delete/:name', requireAdmin, (req, res) => {
  const pkgDir = path.join(CONTENT_DIR, req.params.name);
  if (!path.resolve(pkgDir).startsWith(path.resolve(CONTENT_DIR))) return res.status(400).json({ error: 'Invalid' });
  if (fs.existsSync(pkgDir)) fs.rmSync(pkgDir, { recursive: true });
  res.redirect('/dashboard');
});

// ----- MySQL User Auth -----
const mysql = require('mysql2/promise');

const MYSQL_CONFIG = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: parseInt(process.env.MYSQL_PORT || '3306', 10),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'imd_app',
  waitForConnections: true,
  connectionLimit: 10,
  ...(process.env.MYSQL_SOCKET_PATH ? { socketPath: process.env.MYSQL_SOCKET_PATH } : {}),
};

let mysqlPool = null;

async function getMysqlPool() {
  if (!mysqlPool) {
    mysqlPool = mysql.createPool(MYSQL_CONFIG);
  }
  return mysqlPool;
}

function hashUserPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(String(password), salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_LENGTH, PASSWORD_HASH_DIGEST).toString('hex');
  return { salt, hash };
}

function verifyUserPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const computed = crypto.pbkdf2Sync(String(password), salt, PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_LENGTH, PASSWORD_HASH_DIGEST).toString('hex');
  const a = Buffer.from(computed, 'hex');
  const b = Buffer.from(String(hash), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Middleware: verify mobile app bearer token
async function requireAppAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = authHeader.slice(7);
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT s.id AS session_id, s.user_id, s.device_id, u.username, u.subscription_type, u.subscription_expires, COALESCE(sp.access_level, 1) AS access_level FROM sessions s JOIN users u ON s.user_id = u.id LEFT JOIN subscription_plans sp ON sp.name = u.subscription_type WHERE s.token = ? AND s.is_active = 1 AND s.expires_at > NOW()',
      [token]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.appUser = rows[0];
    next();
  } catch (err) {
    console.error('Auth middleware error:', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// POST /api/auth/login
app.post('/api/auth/login', express.json(), async (req, res) => {
  const { username, password, device_id } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  try {
    const pool = await getMysqlPool();
    const [users] = await pool.execute('SELECT * FROM users WHERE username = ?', [String(username).trim()]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    if (!verifyUserPassword(password, user.password_salt, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!hasActivePaidSubscription(user)) {
      return res.status(402).json({
        error: 'Active paid subscription required. Please sign up and complete payment on the web portal before login.',
        requires_subscription: true,
        signup_url: `${BASE_URL}/signup`,
      });
    }

    // Single-device enforcement: deactivate all existing sessions for this user
    await pool.execute('UPDATE sessions SET is_active = 0 WHERE user_id = ?', [user.id]);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.execute(
      'INSERT INTO sessions (user_id, token, device_id, expires_at, is_active) VALUES (?, ?, ?, ?, 1)',
      [user.id, token, device_id || null, expiresAt]
    );

    const [planRows] = await pool.execute(
      'SELECT access_level FROM subscription_plans WHERE name = ?',
      [user.subscription_type]
    );
    const accessLevel = planRows[0]?.access_level ?? 1;

    res.json({
      token,
      expires_at: expiresAt.toISOString(),
      user: {
        id: user.id,
        username: user.username,
        subscription_type: user.subscription_type,
        subscription_expires: user.subscription_expires,
        access_level: accessLevel,
      },
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('UPDATE sessions SET is_active = 0 WHERE id = ?', [req.appUser.session_id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Logout error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/verify
app.get('/api/auth/verify', requireAppAuth, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.appUser.user_id,
      username: req.appUser.username,
      subscription_type: req.appUser.subscription_type,
      subscription_expires: req.appUser.subscription_expires,
      access_level: req.appUser.access_level ?? 1,
    },
  });
});

// GET /api/auth/account
app.get('/api/auth/account', requireAppAuth, (req, res) => {
  const u = req.appUser;
  res.json({
    id: u.user_id,
    username: u.username,
    subscription_type: u.subscription_type,
    subscription_expires: u.subscription_expires,
    access_level: u.access_level ?? 1,
    device_id: u.device_id,
  });
});

// POST /api/auth/favorites  (add)
app.post('/api/auth/favorites', requireAppAuth, express.json(), async (req, res) => {
  const { package_name } = req.body || {};
  if (!package_name) return res.status(400).json({ error: 'package_name required' });
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT IGNORE INTO favorites (user_id, package_name) VALUES (?, ?)',
      [req.appUser.user_id, package_name]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/auth/favorites/:name
app.delete('/api/auth/favorites/:name', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'DELETE FROM favorites WHERE user_id = ? AND package_name = ?',
      [req.appUser.user_id, req.params.name]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/favorites
app.get('/api/auth/favorites', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT package_name, created_at FROM favorites WHERE user_id = ? ORDER BY created_at DESC',
      [req.appUser.user_id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// TEST HISTORY endpoints
// ══════════════════════════════════════════════════════════════════

// POST /api/auth/test-history — save a completed test
app.post('/api/auth/test-history', requireAppAuth, express.json(), async (req, res) => {
  const { package_name, score, correct, wrong, unanswered, total, mode, question_ids, answers } = req.body || {};
  if (!package_name || total == null) return res.status(400).json({ error: 'package_name and total required' });
  try {
    const pool = await getMysqlPool();
    const [result] = await pool.execute(
      `INSERT INTO test_history (user_id, package_name, score, correct, wrong, unanswered, total, mode, question_ids, answers)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.appUser.user_id, package_name, score || 0, correct || 0, wrong || 0, unanswered || 0, total,
       mode || 'Reading', JSON.stringify(question_ids || []), JSON.stringify(answers || {})]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    console.error('test-history save error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/test-history/:packageName — all tests for a package
app.get('/api/auth/test-history/:packageName', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT id, score, correct, wrong, unanswered, total, mode, created_at FROM test_history WHERE user_id = ? AND package_name = ? ORDER BY created_at DESC',
      [req.appUser.user_id, req.params.packageName]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/test-history/:packageName/last — last test only
app.get('/api/auth/test-history/:packageName/last', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT id, score, correct, wrong, unanswered, total, mode, question_ids, answers, created_at FROM test_history WHERE user_id = ? AND package_name = ? ORDER BY created_at DESC LIMIT 1',
      [req.appUser.user_id, req.params.packageName]
    );
    res.json(rows.length > 0 ? rows[0] : null);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/auth/test-history/:packageName — reset all test history
app.delete('/api/auth/test-history/:packageName', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'DELETE FROM test_history WHERE user_id = ? AND package_name = ?',
      [req.appUser.user_id, req.params.packageName]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/progress/:packageName — aggregated progress
app.get('/api/auth/progress/:packageName', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      `SELECT COUNT(*) as total_tests,
              COALESCE(AVG(score), 0) as avg_score,
              COALESCE(SUM(correct), 0) as total_correct,
              COALESCE(SUM(wrong), 0) as total_wrong,
              COALESCE(SUM(total), 0) as total_questions
       FROM test_history WHERE user_id = ? AND package_name = ?`,
      [req.appUser.user_id, req.params.packageName]
    );
    // Collect all unique question IDs ever attempted
    const [qRows] = await pool.execute(
      'SELECT question_ids FROM test_history WHERE user_id = ? AND package_name = ?',
      [req.appUser.user_id, req.params.packageName]
    );
    const usedSet = new Set();
    for (const r of qRows) {
      try { const ids = typeof r.question_ids === 'string' ? JSON.parse(r.question_ids) : (r.question_ids || []); ids.forEach(id => usedSet.add(id)); } catch (_) {}
    }
    res.json({ ...rows[0], unique_questions_used: usedSet.size });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// QUESTION FAVORITES endpoints
// ══════════════════════════════════════════════════════════════════

// POST /api/auth/question-favorites — toggle (add or remove)
app.post('/api/auth/question-favorites', requireAppAuth, express.json(), async (req, res) => {
  const { package_name, question_id } = req.body || {};
  if (!package_name || question_id == null) return res.status(400).json({ error: 'package_name and question_id required' });
  try {
    const pool = await getMysqlPool();
    // Check if already exists
    const [existing] = await pool.execute(
      'SELECT id FROM question_favorites WHERE user_id = ? AND package_name = ? AND question_id = ?',
      [req.appUser.user_id, package_name, question_id]
    );
    if (existing.length > 0) {
      await pool.execute('DELETE FROM question_favorites WHERE id = ?', [existing[0].id]);
      res.json({ success: true, favorited: false });
    } else {
      await pool.execute(
        'INSERT INTO question_favorites (user_id, package_name, question_id) VALUES (?, ?, ?)',
        [req.appUser.user_id, package_name, question_id]
      );
      res.json({ success: true, favorited: true });
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/question-favorites/:packageName — list favorited question IDs
app.get('/api/auth/question-favorites/:packageName', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT question_id, created_at FROM question_favorites WHERE user_id = ? AND package_name = ? ORDER BY created_at DESC',
      [req.appUser.user_id, req.params.packageName]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/auth/question-favorites/:packageName — delete all question favorites
app.delete('/api/auth/question-favorites/:packageName', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'DELETE FROM question_favorites WHERE user_id = ? AND package_name = ?',
      [req.appUser.user_id, req.params.packageName]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ══════════════════════════════════════════════════════════════════
// BACKUP / RESTORE endpoints
// ══════════════════════════════════════════════════════════════════

// POST /api/auth/backup — create a backup, returns short code
app.post('/api/auth/backup', requireAppAuth, express.json(), async (req, res) => {
  const { package_name, local_favorite_ids, bookmarks, highlights } = req.body || {};
  if (!package_name) return res.status(400).json({ error: 'package_name required' });
  try {
    const pool = await getMysqlPool();
    // Gather test history
    const [tests] = await pool.execute(
      'SELECT score, correct, wrong, unanswered, total, mode, question_ids, answers, created_at FROM test_history WHERE user_id = ? AND package_name = ?',
      [req.appUser.user_id, package_name]
    );
    // Use local favorites sent from client (stored locally on device)
    const favoriteIds = Array.isArray(local_favorite_ids) ? local_favorite_ids : [];
    const localBookmarks = Array.isArray(bookmarks) ? bookmarks : [];
    const localHighlights = Array.isArray(highlights) ? highlights : [];
    const data = {
      test_history: tests,
      local_favorite_ids: favoriteIds,
      bookmarks: localBookmarks,
      highlights: localHighlights,
    };
    // Generate unique 5-char code
    let code;
    for (let i = 0; i < 10; i++) {
      code = crypto.randomBytes(3).toString('base64url').substring(0, 5).toUpperCase();
      const [dup] = await pool.execute('SELECT id FROM backups WHERE backup_code = ?', [code]);
      if (dup.length === 0) break;
    }
    await pool.execute(
      'INSERT INTO backups (user_id, package_name, backup_code, data) VALUES (?, ?, ?, ?)',
      [req.appUser.user_id, package_name, code, JSON.stringify(data)]
    );
    res.json({ success: true, backup_code: code });
  } catch (err) {
    console.error('backup error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/restore — restore from backup code
app.post('/api/auth/restore', requireAppAuth, express.json(), async (req, res) => {
  const { backup_code, package_name } = req.body || {};
  if (!backup_code || !package_name) return res.status(400).json({ error: 'backup_code and package_name required' });
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT data FROM backups WHERE backup_code = ? AND package_name = ?',
      [backup_code, package_name]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Backup not found' });

    const data = typeof rows[0].data === 'string' ? JSON.parse(rows[0].data) : rows[0].data;
    const userId = req.appUser.user_id;

    // Clear existing data for this package
    await pool.execute('DELETE FROM test_history WHERE user_id = ? AND package_name = ?', [userId, package_name]);
    await pool.execute('DELETE FROM question_favorites WHERE user_id = ? AND package_name = ?', [userId, package_name]);

    // Restore test history
    if (data.test_history && data.test_history.length > 0) {
      for (const t of data.test_history) {
        // Convert ISO 8601 datetime to MySQL-compatible format
        let createdAt = t.created_at;
        if (typeof createdAt === 'string' && createdAt.includes('T')) {
          createdAt = createdAt.replace('T', ' ').replace(/\.\d{3}Z$/, '');
        }
        await pool.execute(
          `INSERT INTO test_history (user_id, package_name, score, correct, wrong, unanswered, total, mode, question_ids, answers, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, package_name, t.score, t.correct, t.wrong, t.unanswered || 0, t.total, t.mode,
           typeof t.question_ids === 'string' ? t.question_ids : JSON.stringify(t.question_ids || []),
           typeof t.answers === 'string' ? t.answers : JSON.stringify(t.answers || {}),
           createdAt]
        );
      }
    }

    // Return local favorite IDs from backup so client can restore locally
    const favoriteIds = data.local_favorite_ids || [];
    const restoredBookmarks = data.bookmarks || [];
    const restoredHighlights = data.highlights || [];

    res.json({
      success: true,
      tests_restored: (data.test_history || []).length,
      favorites_restored: favoriteIds.length,
      favorites_restored_ids: favoriteIds,
      bookmarks: restoredBookmarks,
      highlights: restoredHighlights,
    });
  } catch (err) {
    console.error('restore error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/backups/:packageName — list all backups for a package
app.get('/api/auth/backups/:packageName', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT id, backup_code, created_at FROM backups WHERE user_id = ? AND package_name = ? ORDER BY created_at DESC',
      [req.appUser.user_id, req.params.packageName]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/all-backups — get latest backup per package for auto-restore on new device
app.get('/api/auth/all-backups', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      `SELECT b.id, b.package_name, b.backup_code, b.data, b.created_at
       FROM backups b
       INNER JOIN (
         SELECT package_name, MAX(created_at) AS max_created
         FROM backups WHERE user_id = ?
         GROUP BY package_name
       ) latest ON b.package_name = latest.package_name AND b.created_at = latest.max_created
       WHERE b.user_id = ?
       ORDER BY b.created_at DESC`,
      [req.appUser.user_id, req.appUser.user_id]
    );
    const backups = rows.map(r => {
      const data = typeof r.data === 'string' ? JSON.parse(r.data) : r.data;
      return {
        package_name: r.package_name,
        backup_code: r.backup_code,
        created_at: r.created_at,
        test_count: (data.test_history || []).length,
        favorites_count: (data.local_favorite_ids || []).length,
        bookmarks_count: (data.bookmarks || []).length,
        highlights_count: (data.highlights || []).length,
      };
    });
    res.json({ backups });
  } catch (err) {
    console.error('all-backups error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function loadPackageAccessMap() {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT package_name, min_access_level FROM package_access');
    return Object.fromEntries(rows.map(r => [r.package_name, r.min_access_level]));
  } catch (_) {
    return {};
  }
}

// ----- REST API -----
app.get('/api/packages', async (req, res) => {
  const accessMap = await loadPackageAccessMap();
  let packages = loadDashboardPackages()
    .map(({ path: _, ...rest }) => ({ ...rest, minAccessLevel: accessMap[rest.name] ?? 1 }));

  // Server-side search
  const search = String(req.query.search || '').trim().toLowerCase();
  if (search) {
    packages = packages.filter(pkg => {
      const readableName = (pkg.name || '').replace(/[-_]/g, ' ');
      const haystack = [pkg.name, readableName, pkg.category, pkg.type]
        .filter(Boolean).join(' ').toLowerCase();
      return haystack.includes(search);
    });
  }

  // Pagination: ?page=1&limit=20
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));

  const total = packages.length;
  const start = (page - 1) * limit;
  const paged = packages.slice(start, start + limit);

  res.json({ packages: paged, total, page, limit });
});

app.get('/api/packages/:name', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).json({ error: 'Not found' });
  const { path: _, ...safe } = pkg;
  res.json(safe);
});

app.get('/api/packages/:name/icon', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasIcon) return res.status(404).json({ error: 'No icon' });
  res.sendFile(path.join(pkg.path, pkg.iconFile));
});

app.get('/api/packages/:name/subjects', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));
  try {
    const subjects = dbAll(db, 'SELECT * FROM Subjects ORDER BY name');
    db.close();
    res.json(subjects);
  } catch (e) { db.close(); res.json([]); }
});

app.get('/api/packages/:name/systems', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));
  try {
    const systems = dbAll(db, 'SELECT * FROM Systems ORDER BY name');
    db.close();
    res.json(systems);
  } catch (e) { db.close(); res.json([]); }
});

app.get('/api/packages/:name/tests', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));
  try {
    const tests = dbAll(db, 'SELECT * FROM Tests ORDER BY id');
    db.close();
    res.json(tests);
  } catch (e) { db.close(); res.json([]); }
});

app.get('/api/packages/:name/questions', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });

  const db = openDb(path.join(pkg.path, pkg.dbFile));
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = (page - 1) * limit;
  const subject = req.query.subject || '';
  const system = req.query.system || '';

  let where = [], params = {};
  if (subject) { where.push('q.subId = $subject'); params.$subject = parseInt(subject); }
  if (system) { where.push('q.sysId = $system'); params.$system = parseInt(system); }

  const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const total = dbGet(db, `SELECT COUNT(*) as c FROM Questions q ${wc}`, Object.keys(params).length ? params : undefined).c;

  const ap = { ...params, $limit: limit, $offset: offset };
  const rows = dbAll(db, `SELECT q.* FROM Questions q ${wc} ORDER BY q.id LIMIT $limit OFFSET $offset`, ap);

  const questions = rows.map(row => {
    let decQ = '', decE = '';
    const salt = String(row.id);
    try { decQ = decryptText(row.question, salt); } catch (e) { decQ = ''; }
    try { if (row.explanation) decE = decryptText(row.explanation, salt); } catch (e) { decE = ''; }

    const ansRows = dbAll(db, 'SELECT * FROM Answers WHERE qId = $qid ORDER BY answerId', { $qid: row.id });
    const answers = ansRows.map(a => {
      let decA = '';
      try { decA = decryptText(a.answerText, salt); } catch (e) { decA = ''; }
      return { answerId: a.answerId, answerText: decA, isCorrect: a.answerId === row.corrAns };
    });

    return { id: row.id, question: decQ, explanation: decE, subId: row.subId, sysId: row.sysId, corrAns: row.corrAns, mediaName: row.mediaName, otherMedias: row.otherMedias, answers };
  });

  db.close();
  res.json({ total, page, limit, totalPages: Math.ceil(total / limit), questions });
});

app.get('/api/packages/:name/questions/:id', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });

  const db = openDb(path.join(pkg.path, pkg.dbFile));
  const row = dbGet(db, 'SELECT * FROM Questions WHERE id = $id', { $id: parseInt(req.params.id) });
  if (!row) { db.close(); return res.status(404).json({ error: 'Not found' }); }

  const salt = String(row.id);
  let decQ = '', decE = '';
  try { decQ = decryptText(row.question, salt); } catch (e) { decQ = ''; }
  try { if (row.explanation) decE = decryptText(row.explanation, salt); } catch (e) { decE = ''; }

  const ansRows = dbAll(db, 'SELECT * FROM Answers WHERE qId = $qid ORDER BY answerId', { $qid: row.id });
  const answers = ansRows.map(a => {
    let decA = '';
    try { decA = decryptText(a.answerText, salt); } catch (e) { decA = ''; }
    return { answerId: a.answerId, answerText: decA, isCorrect: a.answerId === row.corrAns };
  });

  db.close();
  res.json({ id: row.id, question: decQ, explanation: decE, subId: row.subId, sysId: row.sysId, corrAns: row.corrAns, mediaName: row.mediaName, otherMedias: row.otherMedias, answers });
});

// Serve rendered HTML for a doc (with rewritten media URLs and CSS) — used by Flutter app
app.get('/api/packages/:name/render/:id', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });

  const db = openDb(path.join(pkg.path, pkg.dbFile));
  const content = getReferenceContent(db, parseInt(req.params.id));
  db.close();

  if (!content) return res.status(404).json({ error: 'Content not found' });

  const rewritten = rewritePackageHtml(content.html, pkg.name, content.path);
  res.json({ id: content.id, title: content.title, html: rewritten });
});

// TOC with decrypted titles — used by Flutter for proper navigation ordering
app.get('/api/packages/:name/toc-nav', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });

  const db = openDb(path.join(pkg.path, pkg.dbFile));
  const toc = buildReferenceToc(db);
  const docs = buildReferenceDocs(db);
  db.close();

  // Build ordered list of doc IDs from TOC (leaf nodes only)
  const docIds = new Set(docs.map(d => Number(d.id)));
  const ordered = toc
    .filter(item => item._docId && docIds.has(Number(item._docId)))
    .map(item => ({ docId: Number(item._docId), label: item._label, level: item._level }));

  // Add any docs not in TOC at the end
  const tocDocIds = new Set(ordered.map(o => o.docId));
  for (const d of docs) {
    if (!tocDocIds.has(Number(d.id))) {
      ordered.push({ docId: Number(d.id), label: d.title, level: 0 });
    }
  }

  res.json(ordered);
});

app.get('/api/packages/:name/media/:filename', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).json({ error: 'Not found' });

  const filename = path.basename(req.params.filename);

  // Search multiple possible media directories
  const encryptedDirs = new Set(['media-E', 'Resources-E']);
  const searchDirs = ['media-E', 'Resources-E', 'OEBPS/images', 'OEBPS/Images', 'OEBPS', 'images', 'Images', 'base', '.'];
  let filePath = null;
  let isEncrypted = false;
  for (const dir of searchDirs) {
    const candidate = path.join(pkg.path, dir, filename);
    if (fs.existsSync(candidate) && path.resolve(candidate).startsWith(path.resolve(pkg.path))) {
      filePath = candidate;
      isEncrypted = encryptedDirs.has(dir);
      break;
    }
  }

  if (!filePath) return res.status(404).json({ error: 'Media not found' });

  try {
    let data;
    if (isEncrypted) {
      data = decryptMedia(fs.readFileSync(filePath), filename);
    } else {
      data = fs.readFileSync(filePath);
    }
    let ct = 'application/octet-stream';
    const ext = path.extname(filename).toLowerCase();
    if (data[0] === 0xff && data[1] === 0xd8) ct = 'image/jpeg';
    else if (data[0] === 0x89 && data[1] === 0x50) ct = 'image/png';
    else if (data[0] === 0x47 && data[1] === 0x49) ct = 'image/gif';
    else if (data[0] === 0x42 && data[1] === 0x4d) ct = 'image/bmp';
    else if (ext === '.svg') ct = 'image/svg+xml';
    else if (ext === '.css') ct = 'text/css';
    else if (ext === '.js') ct = 'application/javascript';
    else if (ext === '.html' || ext === '.xhtml') ct = 'text/html';
    res.set('Content-Type', ct);
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(data);
  } catch (e) {
    console.error('Media serve error:', e.message);
    res.status(500).json({ error: 'Failed to serve media' });
  }
});

// ----- Dynamic DB Schema API (works with ANY database) -----
app.get('/api/packages/:name/schema', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));
  const tables = dbAll(db, "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name");
  const schema = [];
  for (const t of tables) {
    try {
      const cols = dbAll(db, `PRAGMA table_info("${t.name}")`);
      const countRow = dbGet(db, `SELECT COUNT(*) as c FROM "${t.name}"`);
      schema.push({ table: t.name, columns: cols.map(c => ({ name: c.name, type: c.type, pk: c.pk })), rowCount: countRow ? countRow.c : 0 });
    } catch (e) {
      // Skip tables that can't be read (e.g. virtual tables with missing modules)
      schema.push({ table: t.name, columns: [], rowCount: 0, error: e.message });
    }
  }
  db.close();
  res.json(schema);
});

// Generic table data endpoint - browse ANY table
app.get('/api/packages/:name/table/:table', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));

  // Validate table exists
  const tableCheck = dbGet(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=$name", { $name: req.params.table });
  if (!tableCheck) { db.close(); return res.status(404).json({ error: 'Table not found' }); }

  const tableName = tableCheck.name;
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 50, 500);
  const offset = (page - 1) * limit;
  const decrypt = req.query.decrypt === 'true';

  const cols = dbAll(db, `PRAGMA table_info("${tableName}")`);
  const total = dbGet(db, `SELECT COUNT(*) as c FROM "${tableName}"`).c;
  let rows = dbAll(db, `SELECT * FROM "${tableName}" LIMIT $limit OFFSET $offset`, { $limit: limit, $offset: offset });

  // Auto-detect and decrypt encrypted fields if requested
  if (decrypt) {
    const pkCol = cols.find(c => c.pk);
    rows = rows.map(row => {
      const salt = pkCol ? String(row[pkCol.name]) : '1';
      const decRow = { ...row };
      for (const col of cols) {
        if (typeof row[col.name] === 'string' && row[col.name].length > 20) {
          try {
            const decoded = Buffer.from(row[col.name], 'base64');
            if (decoded.length > 16 && decoded.length % 16 === 0) {
              decRow[`${col.name}_decrypted`] = decryptText(row[col.name], salt);
            }
          } catch (e) { /* not encrypted */ }
        }
      }
      return decRow;
    });
  }

  db.close();
  res.json({ table: tableName, columns: cols.map(c => ({ name: c.name, type: c.type, pk: c.pk })), total, page, limit, totalPages: Math.ceil(total / limit), rows });
});

// Serve static content files (HTML chapters, CSS, etc.) from package
app.get('/api/packages/:name/file/*', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).json({ error: 'Not found' });

  // req.params[0] contains the rest of the path after /file/
  const relPath = req.params[0];
  const filePath = path.join(pkg.path, relPath);

  // Security: ensure path stays within package directory
  if (!path.resolve(filePath).startsWith(path.resolve(pkg.path))) {
    return res.status(400).json({ error: 'Invalid path' });
  }

  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

  const ext = path.extname(filePath).toLowerCase();
  const contentTypes = {
    '.html': 'text/html', '.xhtml': 'application/xhtml+xml', '.css': 'text/css',
    '.js': 'application/javascript', '.gif': 'image/gif', '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml',
    '.xml': 'application/xml', '.ncx': 'application/xml'
  };
  res.set('Content-Type', contentTypes[ext] || 'application/octet-stream');
  res.set('Cache-Control', 'public, max-age=86400');
  res.sendFile(filePath);
});

// Generic content endpoint - get doc content (decrypt if needed)
app.get('/api/packages/:name/content/:id', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));

  // Try common content tables: Docs, Content, Articles, Pages, Chapters
  const contentTables = ['Docs', 'Content', 'Articles', 'Pages', 'Chapters'];
  let row = null;
  let tableName = null;
  for (const t of contentTables) {
    try {
      row = dbGet(db, `SELECT * FROM "${t}" WHERE id = $id`, { $id: parseInt(req.params.id) });
      if (row) { tableName = t; break; }
    } catch (e) { /* table doesn't exist */ }
  }

  if (!row) { db.close(); return res.status(404).json({ error: 'Content not found' }); }

  const salt = String(row.id);
  const result = { ...row, _table: tableName };

  // Try to decrypt all string fields that look encrypted
  for (const key of Object.keys(row)) {
    if (typeof row[key] === 'string' && row[key].length > 20) {
      try {
        const decoded = Buffer.from(row[key], 'base64');
        if (decoded.length > 16 && decoded.length % 16 === 0) {
          result[`${key}_decrypted`] = decryptText(row[key], salt);
        }
      } catch (e) { /* not encrypted */ }
    }
  }

  // Get TOC/chapters if available
  try {
    const toc = dbAll(db, 'SELECT * FROM TOC WHERE docId = $id ORDER BY id', { $id: parseInt(req.params.id) });
    result._toc = toc;
  } catch (e) { /* no TOC */ }

  db.close();
  res.json(result);
});

// TOC endpoint
app.get('/api/packages/:name/toc', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));
  try {
    const toc = dbAll(db, 'SELECT * FROM TOC ORDER BY id');
    db.close();
    res.json(toc);
  } catch (e) { db.close(); res.json([]); }
});

// Docs list endpoint
app.get('/api/packages/:name/docs', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });
  const db = openDb(path.join(pkg.path, pkg.dbFile));
  try {
    const docs = dbAll(db, 'SELECT * FROM Docs ORDER BY id');
    db.close();
    // Decrypt titles if encrypted
    const result = docs.map(d => {
      const salt = String(d.id);
      const rawTitle = d.title || d.name || `Document ${d.id}`;
      let decTitle = rawTitle;
      try {
        const decoded = Buffer.from(rawTitle, 'base64');
        if (decoded.length > 16 && decoded.length % 16 === 0) {
          decTitle = decryptText(rawTitle, salt);
        }
      } catch (e) { /* not encrypted */ }
      return { id: d.id, title: decTitle, path: d.path || '' };
    });
    res.json(result);
  } catch (e) { db.close(); res.json([]); }
});

// Create a test - returns shuffled/filtered question IDs
app.get('/api/packages/:name/create-test', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database' });

  const db = openDb(path.join(pkg.path, pkg.dbFile));
  const count = Math.min(parseInt(req.query.count) || 40, 200);
  const system = req.query.system || '';
  const sort = req.query.sort || 'random';
  const qids = req.query.qids || '';

  let rows;
  if (qids) {
    // Specific question IDs
    const ids = qids.split(',').map(Number).filter(n => !isNaN(n));
    if (ids.length === 0) { db.close(); return res.json({ questionIds: [] }); }
    const placeholders = ids.map((_, i) => `$id${i}`).join(',');
    const params = {};
    ids.forEach((id, i) => { params[`$id${i}`] = id; });
    rows = dbAll(db, `SELECT id FROM Questions WHERE id IN (${placeholders})`, params);
  } else {
    let where = [], params = {};
    if (system) { where.push('sysId = $system'); params.$system = parseInt(system); }
    const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const orderBy = sort === 'random' ? 'ORDER BY RANDOM()' : 'ORDER BY id';
    rows = dbAll(db, `SELECT id FROM Questions ${wc} ${orderBy} LIMIT $limit`, { ...params, $limit: count });
  }

  db.close();
  res.json({ questionIds: rows.map(r => r.id), count: rows.length });
});

app.get('/api/packages/:name/download', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).json({ error: 'Not found' });
  const zip = new AdmZip();
  zip.addLocalFolder(pkg.path, pkg.name);
  const buf = zip.toBuffer();
  res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${pkg.name}.zip"`, 'Content-Length': buf.length });
  res.send(buf);
});

// ----- BT Guide API -----
// In-memory cache so we don't re-parse BT_config.txt on every request
const _btConfigCache = new Map();
function _getBtScreenMap(pkgPath) {
  if (_btConfigCache.has(pkgPath)) return _btConfigCache.get(pkgPath);
  const cfgPath = path.join(pkgPath, 'BT_config.txt');
  if (!fs.existsSync(cfgPath)) return null;
  const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
  const screens = cfg.BT_appConfig.BT_items[0].BT_screens;
  const smap = {};
  for (const s of screens) smap[s.itemId] = s;
  _btConfigCache.set(pkgPath, smap);
  return smap;
}

app.get('/api/packages/:name/bt-screen/:screenId', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasBtConfig) return res.status(404).json({ error: 'Not a guide package' });
  const smap = _getBtScreenMap(pkg.path);
  if (!smap) return res.status(500).json({ error: 'Failed to parse guide config' });
  const screenId = req.params.screenId;
  const screen = smap[screenId];
  if (!screen) return res.status(404).json({ error: 'Screen not found: ' + screenId });
  const children = (screen.childItems || []).map(c => {
    const target = smap[c.loadScreenWithItemId] || {};
    return {
      itemId: c.itemId,
      targetScreenId: c.loadScreenWithItemId || '',
      itemType: target.itemType || 'BT_menuItem',
      titleText: c.titleText || target.titleText || target.itemNickname || '',
      localFileName: target.localFileName || '',
      hasChildren: (target.childItems || []).length > 0,
    };
  }).filter(c => c.titleText); // skip blanks
  res.json({
    screenId: screen.itemId,
    itemType: screen.itemType,
    titleText: screen.titleText || screen.itemNickname || '',
    localFileName: screen.localFileName || '',
    children,
  });
});

app.get('/api/packages/:name/bt-html/:filename', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).json({ error: 'Package not found' });
  // Sanitize: allow only basename (no path traversal)
  const filename = path.basename(req.params.filename);
  if (!filename || filename.startsWith('.')) return res.status(400).json({ error: 'Invalid filename' });
  const filePath = path.join(pkg.path, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found: ' + filename });
  // Set correct content-type for common extensions
  const ext = path.extname(filename).toLowerCase();
  const mimeMap = { '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif' };
  if (mimeMap[ext]) res.type(mimeMap[ext]);
  res.sendFile(filePath);
});

app.get('/api/packages/:name/download-db', requireAppAuth, async (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database found' });

  // Access-level check
  try {
    const pool = await getMysqlPool();
    const [accessRows] = await pool.execute(
      'SELECT min_access_level FROM package_access WHERE package_name = ?',
      [req.params.name]
    );
    const minLevel = accessRows[0]?.min_access_level ?? 1;
    if ((req.appUser.access_level ?? 1) < minLevel) {
      return res.status(403).json({ error: 'Subscription upgrade required', requires_upgrade: true });
    }
  } catch (err) {
    console.error('Access check error:', err.message);
  }

  // Record the download in MySQL
  try {
    const pool = await getMysqlPool();
    const dbPath = path.join(pkg.path, pkg.dbFile);
    const stat = fs.statSync(dbPath);
    await pool.execute(
      'INSERT INTO user_downloads (user_id, package_name, file_size) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE downloaded_at = NOW(), file_size = ?',
      [req.appUser.user_id, req.params.name, stat.size, stat.size]
    );
    await pool.execute(
      'INSERT INTO download_stats (package_name, download_count) VALUES (?, 1) ON DUPLICATE KEY UPDATE download_count = download_count + 1, last_downloaded = NOW()',
      [req.params.name]
    );
  } catch (err) {
    console.error('Download tracking error:', err.message);
  }

  const dbPath = path.join(pkg.path, pkg.dbFile);
  res.download(dbPath, pkg.dbFile);
});

// ─── App API: User download tracking ───

// GET /api/user/downloads — list all packages the user has downloaded
app.get('/api/user/downloads', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT package_name, downloaded_at, file_size FROM user_downloads WHERE user_id = ? ORDER BY downloaded_at DESC',
      [req.appUser.user_id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/user/downloads/:name — manually record a download
app.post('/api/user/downloads/:name', requireAppAuth, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO user_downloads (user_id, package_name) VALUES (?, ?) ON DUPLICATE KEY UPDATE downloaded_at = NOW()',
      [req.appUser.user_id, req.params.name]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── App API: Tab data endpoints ───

// GET /api/tabs/:tabName — get packages for a specific tab (newest, popular, trending, updates, paid)
app.get('/api/tabs/:tabName', async (req, res) => {
  const tabName = req.params.tabName.toLowerCase();
  const validTabs = ['newest', 'popular', 'trending', 'updates', 'paid'];
  if (!validTabs.includes(tabName)) return res.status(400).json({ error: 'Invalid tab' });

  // Pagination & search params
  const search = String(req.query.search || '').trim().toLowerCase();
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));

  function applySearchAndPaginate(packages) {
    let filtered = packages;
    if (search) {
      filtered = packages.filter(pkg => {
        const readableName = (pkg.name || '').replace(/[-_]/g, ' ');
        const haystack = [pkg.name, readableName, pkg.category, pkg.type]
          .filter(Boolean).join(' ').toLowerCase();
        return haystack.includes(search);
      });
    }
    const total = filtered.length;
    const start = (page - 1) * limit;
    const paged = filtered.slice(start, start + limit);
    return { packages: paged, total, page, limit };
  }

  try {
    const pool = await getMysqlPool();

    // First check if admin has pinned/curated content for this tab
    const [pinned] = await pool.execute(
      'SELECT package_name, sort_order, is_pinned FROM tab_content WHERE tab_name = ? ORDER BY is_pinned DESC, sort_order ASC',
      [tabName]
    );

    const accessMap = await loadPackageAccessMap();
    const allPackages = loadDashboardPackages().map(({ path: _, ...rest }) => ({ ...rest, minAccessLevel: accessMap[rest.name] ?? 1 }));

    if (pinned.length > 0) {
      // Return curated list + remaining packages
      const pinnedNames = new Set(pinned.map(r => r.package_name));
      const pinnedPkgs = pinned.map(r => {
        const pkg = allPackages.find(p => p.name === r.package_name);
        return pkg ? { ...pkg, _pinned: !!r.is_pinned, _sort: r.sort_order } : null;
      }).filter(Boolean);

      // Fill remaining slots with auto-sorted packages
      let remaining = allPackages.filter(p => !pinnedNames.has(p.name));

      if (tabName === 'trending') {
        const [stats] = await pool.execute('SELECT package_name, download_count FROM download_stats ORDER BY download_count DESC');
        const countMap = Object.fromEntries(stats.map(s => [s.package_name, s.download_count]));
        remaining.sort((a, b) => (countMap[b.name] || 0) - (countMap[a.name] || 0));
      }

      res.json(applySearchAndPaginate([...pinnedPkgs, ...remaining]));
      return;
    }

    // Auto-populate based on tab type
    switch (tabName) {
      case 'newest':
        res.json(applySearchAndPaginate(allPackages.sort((a, b) => (b._mtime || 0) - (a._mtime || 0))));
        break;
      case 'popular': {
        const [stats] = await pool.execute('SELECT package_name, download_count FROM download_stats ORDER BY download_count DESC');
        const countMap = Object.fromEntries(stats.map(s => [s.package_name, s.download_count]));
        res.json(applySearchAndPaginate(allPackages.sort((a, b) => (countMap[b.name] || 0) - (countMap[a.name] || 0))));
        break;
      }
      case 'trending': {
        const [recent] = await pool.execute(
          'SELECT package_name, COUNT(*) AS cnt FROM user_downloads WHERE downloaded_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY package_name ORDER BY cnt DESC'
        );
        const trendMap = Object.fromEntries(recent.map(r => [r.package_name, r.cnt]));
        res.json(applySearchAndPaginate(allPackages.sort((a, b) => (trendMap[b.name] || 0) - (trendMap[a.name] || 0))));
        break;
      }
      case 'updates':
        res.json(applySearchAndPaginate(allPackages.sort((a, b) => (b._mtime || 0) - (a._mtime || 0))));
        break;
      case 'paid': {
        const [paid] = await pool.execute(
          'SELECT package_name FROM package_access WHERE min_access_level > 1'
        );
        const paidNames = new Set(paid.map(r => r.package_name));
        res.json(applySearchAndPaginate(allPackages.filter(p => paidNames.has(p.name))));
        break;
      }
      default:
        res.json(applySearchAndPaginate(allPackages));
    }
  } catch (err) {
    console.error('Tab data error:', err.message);
    // Fallback: return all packages with pagination
    let allPackages = loadDashboardPackages().map(({ path: _, ...rest }) => rest);
    if (search) {
      allPackages = allPackages.filter(pkg => {
        const readableName = (pkg.name || '').replace(/[-_]/g, ' ');
        const haystack = [pkg.name, readableName, pkg.category, pkg.type]
          .filter(Boolean).join(' ').toLowerCase();
        return haystack.includes(search);
      });
    }
    const total = allPackages.length;
    const start = (page - 1) * limit;
    const paged = allPackages.slice(start, start + limit);
    res.json({ packages: paged, total, page, limit });
  }
});

// ─── App API: Categories ───

// GET /api/categories — list all active categories
app.get('/api/categories', async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT id, name, sort_order FROM categories WHERE is_active = 1 ORDER BY sort_order ASC'
    );
    res.json(rows);
  } catch (err) {
    // Fallback to hardcoded
    res.json([
      { name: 'Amedex' }, { name: 'NBME' }, { name: 'OVID Books' },
      { name: 'Access Medicine' }, { name: 'Sanford' }, { name: 'Elsevier Videos' },
      { name: 'Elsevier Inc' }, { name: 'PassMedicine' },
    ]);
  }
});

// GET /api/categories/:id/packages — list packages in a category
app.get('/api/categories/:id/packages', async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [mappings] = await pool.execute(
      'SELECT package_name FROM package_categories WHERE category_id = ?',
      [req.params.id]
    );
    const names = new Set(mappings.map(r => r.package_name));
    const allPackages = loadDashboardPackages().map(({ path: _, ...rest }) => rest);
    res.json(allPackages.filter(p => names.has(p.name)));
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Admin API: Helper to log admin actions ───
async function logAdminAction(adminUsername, action, targetType, targetId, details, ip) {
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO admin_logs (admin_username, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
      [adminUsername, action, targetType, targetId, details, ip]
    );
  } catch (err) {
    console.error('Admin log error:', err.message);
  }
}

// ─── Admin API: User Management ───

// GET /api/admin/users — list all users with session info
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [users] = await pool.execute(`
      SELECT u.id, u.username, u.email, u.subscription_type, u.subscription_expires,
             u.is_active, u.created_at, u.updated_at,
             (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.is_active = 1) AS active_sessions,
             (SELECT s.device_id FROM sessions s WHERE s.user_id = u.id AND s.is_active = 1 ORDER BY s.created_at DESC LIMIT 1) AS last_device,
             (SELECT COUNT(*) FROM user_downloads d WHERE d.user_id = u.id) AS download_count
      FROM users u ORDER BY u.created_at DESC
    `);
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users — create a new user
app.post('/api/admin/users', requireAdmin, express.json(), async (req, res) => {
  const { username, password, email, subscription_type, subscription_expires } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const pool = await getMysqlPool();
    const { salt, hash } = hashUserPassword(password);
    await pool.execute(
      'INSERT INTO users (username, email, password_salt, password_hash, subscription_type, subscription_expires) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email || null, salt, hash, subscription_type || 'free', subscription_expires || null]
    );
    await logAdminAction(getAdminSettings().username, 'create_user', 'user', username, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/users/:id — update user
app.put('/api/admin/users/:id', requireAdmin, express.json(), async (req, res) => {
  const { subscription_type, subscription_expires, is_active, password, email } = req.body;
  try {
    const pool = await getMysqlPool();
    const sets = [];
    const params = [];

    if (subscription_type !== undefined) { sets.push('subscription_type = ?'); params.push(subscription_type); }
    if (subscription_expires !== undefined) { sets.push('subscription_expires = ?'); params.push(subscription_expires || null); }
    if (is_active !== undefined) { sets.push('is_active = ?'); params.push(is_active ? 1 : 0); }
    if (email !== undefined) { sets.push('email = ?'); params.push(email || null); }
    if (password) {
      const { salt, hash } = hashUserPassword(password);
      sets.push('password_salt = ?', 'password_hash = ?');
      params.push(salt, hash);
    }

    if (sets.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    params.push(req.params.id);
    await pool.execute(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, params);
    await logAdminAction(getAdminSettings().username, 'update_user', 'user', req.params.id, JSON.stringify(req.body), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users/:id/force-logout — kill all sessions for a user
app.post('/api/admin/users/:id/force-logout', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('UPDATE sessions SET is_active = 0 WHERE user_id = ?', [req.params.id]);
    await logAdminAction(getAdminSettings().username, 'force_logout', 'user', req.params.id, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/users/:id — delete user
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
    await logAdminAction(getAdminSettings().username, 'delete_user', 'user', req.params.id, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin API: Subscription Plans ───

app.get('/api/admin/plans', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT * FROM subscription_plans ORDER BY access_level ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/plans', requireAdmin, express.json(), async (req, res) => {
  const { name, description, duration_days, price, access_level } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO subscription_plans (name, description, duration_days, price, access_level) VALUES (?, ?, ?, ?, ?)',
      [name, description || null, duration_days || 30, price || 0, access_level || 1]
    );
    await logAdminAction(getAdminSettings().username, 'create_plan', 'subscription', name, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/plans/:id', requireAdmin, express.json(), async (req, res) => {
  const { name, description, duration_days, price, access_level, is_active } = req.body;
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'UPDATE subscription_plans SET name=COALESCE(?,name), description=COALESCE(?,description), duration_days=COALESCE(?,duration_days), price=COALESCE(?,price), access_level=COALESCE(?,access_level), is_active=COALESCE(?,is_active) WHERE id=?',
      [name, description, duration_days, price, access_level, is_active, req.params.id]
    );
    await logAdminAction(getAdminSettings().username, 'update_plan', 'subscription', req.params.id, JSON.stringify(req.body), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/plans/:id', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('DELETE FROM subscription_plans WHERE id = ?', [req.params.id]);
    await logAdminAction(getAdminSettings().username, 'delete_plan', 'subscription', req.params.id, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin API: Package Access Control ───

app.get('/api/admin/package-access', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT * FROM package_access ORDER BY package_name');
    const allPackages = loadDashboardPackages().map(p => p.name);
    // Merge: show all packages, marking those with custom access rules
    const accessMap = Object.fromEntries(rows.map(r => [r.package_name, r]));
    const result = allPackages.map(name => ({
      name,
      min_access_level: accessMap[name]?.min_access_level ?? 1,
      is_visible: accessMap[name]?.is_visible ?? 1,
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/package-access/:name', requireAdmin, express.json(), async (req, res) => {
  const { min_access_level, is_visible } = req.body;
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO package_access (package_name, min_access_level, is_visible) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE min_access_level = VALUES(min_access_level), is_visible = VALUES(is_visible)',
      [req.params.name, min_access_level ?? 1, is_visible ?? 1]
    );
    await logAdminAction(getAdminSettings().username, 'update_access', 'package', req.params.name, JSON.stringify(req.body), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin API: Tab Content Management ───

app.get('/api/admin/tabs', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT * FROM tab_content ORDER BY tab_name, is_pinned DESC, sort_order ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/tabs', requireAdmin, express.json(), async (req, res) => {
  const { tab_name, package_name, sort_order, is_pinned } = req.body;
  if (!tab_name || !package_name) return res.status(400).json({ error: 'tab_name and package_name required' });
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO tab_content (tab_name, package_name, sort_order, is_pinned) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE sort_order = VALUES(sort_order), is_pinned = VALUES(is_pinned)',
      [tab_name, package_name, sort_order || 0, is_pinned || 0]
    );
    await logAdminAction(getAdminSettings().username, 'update_tab', 'tab', tab_name, JSON.stringify(req.body), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/tabs/:id', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('DELETE FROM tab_content WHERE id = ?', [req.params.id]);
    await logAdminAction(getAdminSettings().username, 'delete_tab_item', 'tab', req.params.id, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin API: Categories Management ───

app.get('/api/admin/categories', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT * FROM categories ORDER BY sort_order ASC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/categories', requireAdmin, express.json(), async (req, res) => {
  const { name, sort_order } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  try {
    const pool = await getMysqlPool();
    await pool.execute('INSERT INTO categories (name, sort_order) VALUES (?, ?)', [name, sort_order || 0]);
    await logAdminAction(getAdminSettings().username, 'create_category', 'category', name, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/categories/:id', requireAdmin, express.json(), async (req, res) => {
  const { name, sort_order, is_active } = req.body;
  try {
    const pool = await getMysqlPool();
    await pool.execute(
      'UPDATE categories SET name=COALESCE(?,name), sort_order=COALESCE(?,sort_order), is_active=COALESCE(?,is_active) WHERE id=?',
      [name, sort_order, is_active, req.params.id]
    );
    await logAdminAction(getAdminSettings().username, 'update_category', 'category', req.params.id, JSON.stringify(req.body), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/categories/:id', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('DELETE FROM categories WHERE id = ?', [req.params.id]);
    await logAdminAction(getAdminSettings().username, 'delete_category', 'category', req.params.id, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/categories/:id/packages — assign packages to category
app.post('/api/admin/categories/:id/packages', requireAdmin, express.json(), async (req, res) => {
  const { package_names } = req.body; // array of package names
  if (!Array.isArray(package_names)) return res.status(400).json({ error: 'package_names array required' });
  try {
    const pool = await getMysqlPool();
    // Clear existing and re-insert
    await pool.execute('DELETE FROM package_categories WHERE category_id = ?', [req.params.id]);
    for (const name of package_names) {
      await pool.execute(
        'INSERT IGNORE INTO package_categories (package_name, category_id) VALUES (?, ?)',
        [name, req.params.id]
      );
    }
    await logAdminAction(getAdminSettings().username, 'assign_packages', 'category', req.params.id, JSON.stringify(package_names), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin API: Analytics Dashboard ───

app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [[{ total_users }]] = await pool.execute('SELECT COUNT(*) AS total_users FROM users');
    const [[{ active_users }]] = await pool.execute('SELECT COUNT(*) AS active_users FROM users WHERE is_active = 1');
    const [[{ total_downloads }]] = await pool.execute('SELECT COALESCE(SUM(download_count), 0) AS total_downloads FROM download_stats');
    const [[{ active_sessions }]] = await pool.execute('SELECT COUNT(*) AS active_sessions FROM sessions WHERE is_active = 1 AND expires_at > NOW()');

    const [subCounts] = await pool.execute(
      'SELECT subscription_type, COUNT(*) AS count FROM users GROUP BY subscription_type'
    );
    const [topDownloads] = await pool.execute(
      'SELECT package_name, download_count FROM download_stats ORDER BY download_count DESC LIMIT 10'
    );
    const [recentActivity] = await pool.execute(
      'SELECT action, target_type, target_id, admin_username, created_at FROM admin_logs ORDER BY created_at DESC LIMIT 20'
    );
    const [recentDownloads] = await pool.execute(
      'SELECT u.username, d.package_name, d.downloaded_at FROM user_downloads d JOIN users u ON d.user_id = u.id ORDER BY d.downloaded_at DESC LIMIT 20'
    );

    res.json({
      total_users,
      active_users,
      total_downloads,
      active_sessions,
      subscription_counts: subCounts,
      top_downloads: topDownloads,
      recent_activity: recentActivity,
      recent_downloads: recentDownloads,
      total_packages: loadDashboardPackages().length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin API: Logs ───

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 500);
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT ?',
      [limit]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════
// ─── Admin: Revenue, Notifications, Settings, Subscriptions ───
// ═══════════════════════════════════════════════════════════

// GET /api/admin/revenue
app.get('/api/admin/revenue', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [[{ total_revenue }]] = await pool.execute('SELECT COALESCE(SUM(amount),0) AS total_revenue FROM payments WHERE status=?', ['completed']);
    const [[{ monthly_revenue }]] = await pool.execute(
      'SELECT COALESCE(SUM(amount),0) AS monthly_revenue FROM payments WHERE status=? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)', ['completed']
    );
    const [revenueByMonth] = await pool.execute(
      "SELECT DATE_FORMAT(created_at, '%Y-%m') AS month, SUM(amount) AS revenue FROM payments WHERE status='completed' GROUP BY month ORDER BY month DESC LIMIT 12"
    );
    const [revenueByPlan] = await pool.execute(
      "SELECT sp.name, COUNT(*) AS count, SUM(p.amount) AS revenue FROM payments p JOIN subscription_plans sp ON p.plan_id=sp.id WHERE p.status='completed' GROUP BY sp.name"
    );
    res.json({ total_revenue, monthly_revenue, revenue_by_month: revenueByMonth, revenue_by_plan: revenueByPlan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/subscriptions
app.get('/api/admin/subscriptions', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT u.id, u.username, u.email, u.full_name, u.subscription_type, u.subscription_expires, u.subscription_status, u.auto_renew, u.created_at FROM users WHERE subscription_type!=? ORDER BY u.created_at DESC',
      ['free']
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/refund/:id
app.post('/api/admin/refund/:id', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [[payment]] = await pool.execute('SELECT * FROM payments WHERE id=?', [req.params.id]);
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    if (payment.status === 'refunded') return res.status(400).json({ error: 'Already refunded' });

    if (payment.stripe_payment_id && process.env.STRIPE_SECRET_KEY) {
      await stripe.refunds.create({ payment_intent: payment.stripe_payment_id });
    }

    await pool.execute('UPDATE payments SET status=? WHERE id=?', ['refunded', req.params.id]);
    await logAdminAction(getAdminSettings().username, 'refund_payment', 'payment', req.params.id, JSON.stringify({ amount: payment.amount, user_id: payment.user_id }), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/extend-subscription/:userId
app.post('/api/admin/extend-subscription/:userId', requireAdmin, async (req, res) => {
  const { plan_id, days } = req.body || {};
  if (!days && !plan_id) return res.status(400).json({ error: 'days or plan_id required' });

  try {
    const pool = await getMysqlPool();
    const [[user]] = await pool.execute('SELECT * FROM users WHERE id=?', [req.params.userId]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    let newExpiry;
    const currentExpiry = user.subscription_expires ? new Date(user.subscription_expires) : new Date();
    const base = currentExpiry > new Date() ? currentExpiry : new Date();

    if (days) {
      newExpiry = new Date(base.getTime() + parseInt(days) * 86400000);
    } else if (plan_id) {
      const [[plan]] = await pool.execute('SELECT duration_days FROM subscription_plans WHERE id=?', [plan_id]);
      if (!plan) return res.status(404).json({ error: 'Plan not found' });
      newExpiry = new Date(base.getTime() + plan.duration_days * 86400000);
    }

    await pool.execute(
      'UPDATE users SET subscription_type=?, subscription_expires=?, subscription_status=? WHERE id=?',
      ['premium', newExpiry.toISOString().split('T')[0], 'active', req.params.userId]
    );
    await logAdminAction(getAdminSettings().username, 'extend_subscription', 'user', req.params.userId, JSON.stringify({ new_expiry: newExpiry.toISOString().split('T')[0] }), req.ip);
    res.json({ success: true, new_expiry: newExpiry.toISOString().split('T')[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/notifications
app.get('/api/admin/notifications', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT * FROM admin_notifications ORDER BY created_at DESC LIMIT 50');
    const [[{ unread }]] = await pool.execute('SELECT COUNT(*) AS unread FROM admin_notifications WHERE is_read=0');
    res.json({ notifications: rows, unread });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/notifications/:id/read
app.put('/api/admin/notifications/:id/read', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('UPDATE admin_notifications SET is_read=1 WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/notifications/read-all
app.put('/api/admin/notifications/read-all', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('UPDATE admin_notifications SET is_read=1');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/settings
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute('SELECT setting_key, setting_value FROM app_settings');
    const settings = {};
    rows.forEach(r => { settings[r.setting_key] = r.setting_value; });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/settings
app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  const updates = req.body || {};
  try {
    const pool = await getMysqlPool();
    for (const [key, value] of Object.entries(updates)) {
      const safeKey = String(key).slice(0, 100);
      const safeValue = String(value).slice(0, 5000);
      await pool.execute(
        'INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?) ON DUPLICATE KEY UPDATE setting_value=?',
        [safeKey, safeValue, safeValue]
      );
    }
    await logAdminAction(getAdminSettings().username, 'update_settings', 'settings', null, JSON.stringify(Object.keys(updates)), req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Admin pages (new views) ───
app.get('/admin/users', requireAdmin, (req, res) => {
  res.render('users', { currentAdminUser: getAdminSettings().username });
});

app.get('/admin/subscriptions', requireAdmin, (req, res) => {
  res.render('subscriptions', { stripeKey: process.env.STRIPE_PUBLISHABLE_KEY || '', currentAdminUser: getAdminSettings().username });
});

app.get('/admin/content', requireAdmin, (req, res) => {
  res.redirect('/dashboard');
});

app.get('/admin/analytics', requireAdmin, (req, res) => {
  res.render('analytics', { currentAdminUser: getAdminSettings().username });
});

app.get('/admin/settings', requireAdmin, (req, res) => {
  res.render('settings', { stripeKey: process.env.STRIPE_PUBLISHABLE_KEY || '', currentAdminUser: getAdminSettings().username });
});

// POST /api/admin/sessions/expire-all
app.post('/api/admin/sessions/expire-all', requireAdmin, async (req, res) => {
  try {
    const pool = await getMysqlPool();
    await pool.execute('UPDATE sessions SET is_active=0 WHERE is_active=1');
    await logAdminAction(getAdminSettings().username, 'expire_all_sessions', 'sessions', null, null, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Subscription Expiry Cron (runs every hour) ───
setInterval(async () => {
  try {
    const pool = await getMysqlPool();
    const [expired] = await pool.execute(
      "SELECT id, username FROM users WHERE subscription_expires < NOW() AND subscription_type != 'free' AND subscription_status != 'expired'"
    );
    if (expired.length > 0) {
      await pool.execute(
        "UPDATE users SET subscription_type='free', subscription_status='expired' WHERE subscription_expires < NOW() AND subscription_type != 'free' AND subscription_status != 'expired'"
      );
      for (const u of expired) {
        await pool.execute(
          'INSERT INTO admin_notifications (type, title, message, data) VALUES (?,?,?,?)',
          ['subscription_expired', 'Subscription Expired', `User ${u.username} (#${u.id}) subscription expired`, JSON.stringify({ user_id: u.id })]
        );
      }
      console.log(`[Cron] Expired ${expired.length} subscriptions`);
    }
  } catch (err) {
    console.error('[Cron] Subscription expiry check failed:', err.message);
  }
}, 60 * 60 * 1000); // every hour

async function start() {
  SQL = await initSqlJs();
  app.listen(PORT, () => console.log(`Admin panel running at http://localhost:${PORT}`));
}
start();
