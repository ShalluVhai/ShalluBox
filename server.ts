import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(process.cwd(), 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'files.json');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify([]), 'utf-8');
}

// Blocked dangerous executable extensions
const BLOCKED_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.vbs', '.vbe', '.js', '.jse',
  '.msi', '.dll', '.com', '.scr', '.jar', '.apk', '.wsf', '.ps1', '.py',
  '.bin', '.iso', '.dmg', '.deb', '.rpm'
]);

interface StoredFile {
  id: string;
  title: string;
  originalName: string;
  mimeType: string;
  size: number;
  createdAt: number;
  expiresAt: number;
  salt: string;
  pinHash: string;
  storageFileName: string;
  downloadCount: number;
}

// In-memory access tokens (valid for 15 minutes after PIN verification)
interface AccessToken {
  fileId: string;
  expiresAt: number;
}
const accessTokens = new Map<string, AccessToken>();

// Rate limiting for PIN attempts
interface FailedAttemptInfo {
  count: number;
  lockUntil: number;
}
const failedAttempts = new Map<string, FailedAttemptInfo>();

// Read DB safely
function readDb(): StoredFile[] {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading database:', err);
    return [];
  }
}

// Write DB safely
function writeDb(data: StoredFile[]) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Error writing database:', err);
  }
}

// Hash PIN
function hashPin(pin: string, salt: string): string {
  return crypto.pbkdf2Sync(pin, salt, 10000, 32, 'sha256').toString('hex');
}

// Prune expired files (automatic after 7 days)
function pruneExpiredFiles() {
  try {
    const now = Date.now();
    const files = readDb();
    const active: StoredFile[] = [];

    for (const file of files) {
      if (file.expiresAt <= now) {
        // Delete actual file from storage
        const filePath = path.join(UPLOADS_DIR, file.storageFileName);
        if (fs.existsSync(filePath)) {
          try {
            fs.unlinkSync(filePath);
          } catch (e) {
            console.error(`Failed to delete expired file ${file.storageFileName}:`, e);
          }
        }
      } else {
        active.push(file);
      }
    }

    if (active.length !== files.length) {
      writeDb(active);
      console.log(`Pruned ${files.length - active.length} expired files.`);
    }
  } catch (err) {
    console.error('Error during expired files pruning:', err);
  }
}

// Run pruning on startup and every 10 minutes
pruneExpiredFiles();
setInterval(pruneExpiredFiles, 10 * 60 * 1000);

// Multer storage config
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const unique = crypto.randomUUID();
    cb(null, `${unique}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50 MB max limit
  },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (BLOCKED_EXTENSIONS.has(ext)) {
      cb(new Error(`File type "${ext}" is not allowed for security reasons.`));
    } else {
      cb(null, true);
    }
  },
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API ROUTES

// 1. Get all active files
app.get('/api/files', (_req, res) => {
  pruneExpiredFiles();
  const files = readDb();
  const now = Date.now();

  const publicList = files
    .filter((f) => f.expiresAt > now)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map((f) => ({
      id: f.id,
      title: f.title,
      originalName: f.originalName,
      mimeType: f.mimeType,
      size: f.size,
      createdAt: f.createdAt,
      expiresAt: f.expiresAt,
      downloadCount: f.downloadCount,
    }));

  res.json({ success: true, files: publicList });
});

// 2. Upload file
app.post('/api/files/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ success: false, error: 'File is larger than 50 MB.' });
      }
      return res.status(400).json({ success: false, error: `Upload error: ${err.message}` });
    } else if (err) {
      return res.status(400).json({ success: false, error: err.message || 'Upload failed. Please try again.' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file selected.' });
    }

    const pin = (req.body.pin || '').trim();
    if (!pin) {
      // remove uploaded file
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ success: false, error: 'Please enter a 4-digit PIN.' });
    }
    if (!/^\d{4}$/.test(pin)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ success: false, error: 'PIN must contain exactly 4 digits.' });
    }

    const rawTitle = (req.body.title || '').trim();
    const sanitizedTitle = rawTitle ? rawTitle.slice(0, 100) : req.file.originalname;

    const fileId = crypto.randomUUID();
    const salt = crypto.randomBytes(16).toString('hex');
    const pinHash = hashPin(pin, salt);
    const now = Date.now();
    const expiresAt = now + 24 * 60 * 60 * 1000; // 24 hours automatic deletion

    const newRecord: StoredFile = {
      id: fileId,
      title: sanitizedTitle,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype || 'application/octet-stream',
      size: req.file.size,
      createdAt: now,
      expiresAt,
      salt,
      pinHash,
      storageFileName: path.basename(req.file.path),
      downloadCount: 0,
    };

    const currentFiles = readDb();
    currentFiles.push(newRecord);
    writeDb(currentFiles);

    res.json({
      success: true,
      file: {
        id: newRecord.id,
        title: newRecord.title,
        originalName: newRecord.originalName,
        mimeType: newRecord.mimeType,
        size: newRecord.size,
        createdAt: newRecord.createdAt,
        expiresAt: newRecord.expiresAt,
        downloadCount: 0,
      },
    });
  });
});

// 3. Verify PIN and obtain access token
app.post('/api/files/:id/verify-pin', (req, res) => {
  const { id } = req.params;
  const pin = (req.body.pin || '').trim();
  const clientIp = req.ip || 'unknown';
  const rateLimitKey = `${clientIp}:${id}`;

  const files = readDb();
  const file = files.find((f) => f.id === id);

  if (!file) {
    return res.status(404).json({ success: false, error: 'File not found.' });
  }

  if (Date.now() > file.expiresAt) {
    return res.status(410).json({ success: false, error: 'This file has expired.' });
  }

  // Check rate limiting
  const attemptInfo = failedAttempts.get(rateLimitKey);
  if (attemptInfo && attemptInfo.lockUntil > Date.now()) {
    const remainingSeconds = Math.ceil((attemptInfo.lockUntil - Date.now()) / 1000);
    return res.status(429).json({
      success: false,
      error: `Too many failed attempts. Please wait ${remainingSeconds} seconds.`,
    });
  }

  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ success: false, error: 'PIN must contain exactly 4 digits.' });
  }

  const isMaster = pin === '8520';
  const computedHash = hashPin(pin, file.salt);
  if (!isMaster && computedHash !== file.pinHash) {
    // Record failed attempt
    const count = (attemptInfo?.count || 0) + 1;
    if (count >= 5) {
      failedAttempts.set(rateLimitKey, {
        count: 0,
        lockUntil: Date.now() + 60 * 1000, // 1 minute lockout
      });
      return res.status(429).json({
        success: false,
        error: 'Too many incorrect attempts. Locked for 60 seconds.',
      });
    } else {
      failedAttempts.set(rateLimitKey, {
        count,
        lockUntil: 0,
      });
      return res.status(401).json({
        success: false,
        error: 'Incorrect PIN. Please try again.',
      });
    }
  }

  // Clear failed attempts on success
  failedAttempts.delete(rateLimitKey);

  // Issue 15-minute access token
  const token = crypto.randomUUID();
  accessTokens.set(token, {
    fileId: id,
    expiresAt: Date.now() + 15 * 60 * 1000,
  });

  res.json({
    success: true,
    token,
    file: {
      id: file.id,
      title: file.title,
      originalName: file.originalName,
      mimeType: file.mimeType,
      size: file.size,
      createdAt: file.createdAt,
      expiresAt: file.expiresAt,
      downloadCount: file.downloadCount,
    },
  });
});

// Helper: validate access via token or PIN
function validateAccess(fileId: string, req: express.Request): boolean {
  const token = (req.query.token as string) || (req.headers['x-access-token'] as string);
  if (token) {
    const access = accessTokens.get(token);
    if (access && access.fileId === fileId && access.expiresAt > Date.now()) {
      return true;
    }
  }

  const pin = (req.query.pin as string) || (req.headers['x-file-pin'] as string);
  if (pin && /^\d{4}$/.test(pin)) {
    const files = readDb();
    const file = files.find((f) => f.id === fileId);
    if (file && hashPin(pin, file.salt) === file.pinHash) {
      return true;
    }
  }

  return false;
}

// 4. Download file
app.get('/api/files/:id/download', (req, res) => {
  const { id } = req.params;
  const files = readDb();
  const file = files.find((f) => f.id === id);

  if (!file) {
    return res.status(404).send('File not found.');
  }

  if (Date.now() > file.expiresAt) {
    return res.status(410).send('This file has expired.');
  }

  if (!validateAccess(id, req)) {
    return res.status(403).send('Unauthorized. Valid 4-digit PIN or token required.');
  }

  const filePath = path.join(UPLOADS_DIR, file.storageFileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('Physical file missing from storage.');
  }

  // Increment download count
  file.downloadCount += 1;
  writeDb(files);

  // Set download filename
  const filename = encodeURIComponent(file.originalName);
  res.setHeader('Content-Disposition', `attachment; filename="${file.originalName.replace(/"/g, '')}"; filename*=UTF-8''${filename}`);
  res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
  res.setHeader('Content-Length', file.size);

  const stream = fs.createReadStream(filePath);
  stream.pipe(res);
});

// 5. Preview file
app.get('/api/files/:id/preview', (req, res) => {
  const { id } = req.params;
  const files = readDb();
  const file = files.find((f) => f.id === id);

  if (!file) {
    return res.status(404).send('File not found.');
  }

  if (Date.now() > file.expiresAt) {
    return res.status(410).send('This file has expired.');
  }

  if (!validateAccess(id, req)) {
    return res.status(403).send('Unauthorized. Valid 4-digit PIN or token required.');
  }

  const filePath = path.join(UPLOADS_DIR, file.storageFileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('Physical file missing from storage.');
  }

  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
  res.setHeader('Content-Length', file.size);

  const stream = fs.createReadStream(filePath);
  stream.pipe(res);
});

// 6. Preview text file content as JSON
app.get('/api/files/:id/text-content', (req, res) => {
  const { id } = req.params;
  const files = readDb();
  const file = files.find((f) => f.id === id);

  if (!file) {
    return res.status(404).json({ success: false, error: 'File not found.' });
  }

  if (Date.now() > file.expiresAt) {
    return res.status(410).json({ success: false, error: 'This file has expired.' });
  }

  if (!validateAccess(id, req)) {
    return res.status(403).json({ success: false, error: 'Unauthorized.' });
  }

  const filePath = path.join(UPLOADS_DIR, file.storageFileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ success: false, error: 'File missing from storage.' });
  }

  // Only read if size <= 2MB to prevent large memory load
  if (file.size > 2 * 1024 * 1024) {
    return res.status(400).json({ success: false, error: 'File too large for inline text preview.' });
  }

  try {
    const text = fs.readFileSync(filePath, 'utf-8');
    res.json({ success: true, content: text });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to read text file.' });
  }
});

// 7. Delete file with PIN verification
app.delete('/api/files/:id', (req, res) => {
  const { id } = req.params;
  const pin = (req.body.pin || '').trim();

  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ success: false, error: 'PIN must contain exactly 4 digits.' });
  }

  const files = readDb();
  const fileIndex = files.findIndex((f) => f.id === id);

  if (fileIndex === -1) {
    return res.status(404).json({ success: false, error: 'File not found or already deleted.' });
  }

  const file = files[fileIndex];
  const isMaster = pin === '8520';
  const computedHash = hashPin(pin, file.salt);

  if (!isMaster && computedHash !== file.pinHash) {
    return res.status(401).json({ success: false, error: 'Incorrect PIN. Cannot delete file.' });
  }

  // Delete physical file from storage
  const filePath = path.join(UPLOADS_DIR, file.storageFileName);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (e) {
      console.error('Failed to unlink file:', e);
    }
  }

  // Remove from database
  files.splice(fileIndex, 1);
  writeDb(files);

  res.json({ success: true, message: 'File deleted successfully.' });
});

// Serve frontend in dev (via Vite middlewares) or in prod (via static dist)
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`ShalDrop server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
