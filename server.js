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
const PORT = 3000;
const execFileAsync = promisify(execFile);

let SQL;

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
    const contentCandidates = ['doc', 'content', 'html', 'body', 'text', 'data'];
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

// ----- Middleware -----
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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

function hasExtractedContent(dirPath) {
  if (!fs.existsSync(dirPath)) return false;
  return getVisibleEntries(dirPath).length > 0;
}

function resolveExtractedPackage(tempExtractDir, fallbackName) {
  const entries = getVisibleEntries(tempExtractDir);

  if (entries.length === 1 && entries[0].isDirectory()) {
    return {
      packageName: sanitizePackageName(entries[0].name),
      sourceDir: path.join(tempExtractDir, entries[0].name),
    };
  }

  return {
    packageName: sanitizePackageName(fallbackName),
    sourceDir: tempExtractDir,
  };
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

  return packageName;
}

function wantsHtmlResponse(req) {
  const accept = String(req.headers.accept || '').toLowerCase();
  return accept.includes('text/html');
}

function buildUploadRedirectUrl(message, isError) {
  const params = new URLSearchParams();
  params.set(isError ? 'uploadError' : 'uploadSuccess', message);
  return `/upload?${params.toString()}`;
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

function getPackageInfo(pkgName) {
  const pkgDir = path.join(CONTENT_DIR, pkgName);
  if (!fs.existsSync(pkgDir)) return null;

  const info = { name: pkgName, path: pkgDir, hasDb: false, hasMedia: false, hasIcon: false, questionCount: 0, subjectCount: 0, systemCount: 0, mediaCount: 0, tables: [], type: 'other', category: 'General' };
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

  // Check for media in media-E/ or OEBPS/images/ or images/
  const mediaDirs = ['media-E', 'OEBPS/images', 'images', 'OEBPS/Images'];
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
    info.hasDb = false; // override — no SQLite DB
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

  return info;
}

function loadDashboardPackages() {
  return fs.readdirSync(CONTENT_DIR)
    .filter(f => fs.statSync(path.join(CONTENT_DIR, f)).isDirectory())
    .map(getPackageInfo)
    .filter(Boolean);
}

// ----- Admin routes -----
app.get('/', (req, res) => {
  res.redirect('/upload');
});

app.get('/upload', (req, res) => {
  const packages = loadDashboardPackages();

  // Count stale zero-byte files in uploads dir
  let staleCount = 0;
  const uploadsDir = path.join(__dirname, 'uploads');
  if (fs.existsSync(uploadsDir)) {
    try {
      const files = fs.readdirSync(uploadsDir);
      for (const f of files) {
        try {
          const stat = fs.statSync(path.join(uploadsDir, f));
          if (stat.isFile() && stat.size === 0) staleCount++;
        } catch (_) {}
      }
    } catch (_) {}
  }

  res.render('dashboard', {
    packages,
    uploadError: req.query.uploadError || '',
    uploadSuccess: req.query.uploadSuccess || '',
    staleCount,
  });
});

app.post('/cleanup-uploads', (req, res) => {
  const uploadsDir = path.join(__dirname, 'uploads');
  let removed = 0;
  if (fs.existsSync(uploadsDir)) {
    try {
      const files = fs.readdirSync(uploadsDir);
      for (const f of files) {
        const fp = path.join(uploadsDir, f);
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

app.get('/package/:name', (req, res) => {
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

app.post('/upload', (req, res, next) => {
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

app.post('/delete/:name', (req, res) => {
  const pkgDir = path.join(CONTENT_DIR, req.params.name);
  if (!path.resolve(pkgDir).startsWith(path.resolve(CONTENT_DIR))) return res.status(400).json({ error: 'Invalid' });
  if (fs.existsSync(pkgDir)) fs.rmSync(pkgDir, { recursive: true });
  res.redirect('/');
});

// ----- REST API -----
app.get('/api/packages', (req, res) => {
  const packages = fs.readdirSync(CONTENT_DIR)
    .filter(f => fs.statSync(path.join(CONTENT_DIR, f)).isDirectory())
    .map(getPackageInfo).filter(Boolean)
    .map(({ path: _, ...rest }) => rest);
  res.json(packages);
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

app.get('/api/packages/:name/media/:filename', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg) return res.status(404).json({ error: 'Not found' });

  const filename = path.basename(req.params.filename);

  // Search multiple possible media directories
  const searchDirs = ['media-E', 'OEBPS/images', 'OEBPS/Images', 'OEBPS', 'images', 'Images', 'base', '.'];
  let filePath = null;
  let isEncrypted = false;
  for (const dir of searchDirs) {
    const candidate = path.join(pkg.path, dir, filename);
    if (fs.existsSync(candidate) && path.resolve(candidate).startsWith(path.resolve(pkg.path))) {
      filePath = candidate;
      isEncrypted = dir === 'media-E'; // only media-E contains encrypted files
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
    const docs = dbAll(db, 'SELECT id, title, path FROM Docs ORDER BY id');
    db.close();
    // Decrypt titles if encrypted
    const result = docs.map(d => {
      const salt = String(d.id);
      let decTitle = d.title;
      try {
        const decoded = Buffer.from(d.title, 'base64');
        if (decoded.length > 16 && decoded.length % 16 === 0) {
          decTitle = decryptText(d.title, salt);
        }
      } catch (e) { /* not encrypted */ }
      return { ...d, title: decTitle };
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
  res.sendFile(filePath);
});

app.get('/api/packages/:name/download-db', (req, res) => {
  const pkg = getPackageInfo(req.params.name);
  if (!pkg || !pkg.hasDb) return res.status(404).json({ error: 'No database found' });
  const dbPath = path.join(pkg.path, pkg.dbFile);
  res.download(dbPath, pkg.dbFile);
});

async function start() {
  SQL = await initSqlJs();
  app.listen(PORT, () => console.log(`Admin panel running at http://localhost:${PORT}`));
}
start();
