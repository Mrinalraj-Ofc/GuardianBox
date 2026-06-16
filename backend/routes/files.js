/**
 * routes/files.js — GuardianBox File API Routes
 * ──────────────────────────────────────────────
 * POST   /api/files/upload    → receives encrypted blob + metadata
 * GET    /api/files/:id       → serves encrypted blob to recipient
 * DELETE /api/files/:id       → owner-initiated delete (optional)
 * GET    /api/files/:id/meta  → returns metadata needed for UI (no blob)
 *
 * The server NEVER inspects the blob content. It is treated as opaque bytes.
 */

import express  from 'express';
import multer   from 'multer';
import { v4 as uuidv4 } from 'uuid';
import {
  insertFile,
  getFileById,
  incrementDownload,
  deleteFile,
} from '../db.js';
import {
  uploadEncryptedBlob,
  streamEncryptedBlob,
  deleteBlob,
  objectExists,
} from '../storage.js';
import { validateUploadMetadata } from '../middleware/validate.js';

const router = express.Router();

// ─── Multer Configuration ─────────────────────────────────────────────────────

/**
 * Multer streams the upload into memory.
 * For production, use multer-s3 to stream directly to S3 without buffering.
 *
 * Max file size: 100MB (adjustable via env)
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: parseInt(process.env.MAX_FILE_SIZE || '104857600') }, // 100 MB
  fileFilter: (req, file, cb) => {
    // We accept any file type because we can't/shouldn't inspect content
    cb(null, true);
  },
});

// ─── POST /api/files/upload ───────────────────────────────────────────────────

/**
 * Upload encrypted file blob + metadata.
 *
 * Expected multipart/form-data fields:
 *  - file          : binary (the encrypted blob — opaque bytes)
 *  - iv            : string (base64url, 12 bytes)
 *  - salt          : string (base64url, 16 bytes)
 *  - originalName  : string (filename for download prompt)
 *  - mimetype      : string (MIME type for download prompt)
 *  - expiresIn     : number (seconds from now, 0 = never)
 *  - maxDownloads  : number (0 = unlimited; N = burn after N reads)
 *
 * The server stores ALL of the above EXCEPT it never sees the key.
 * The key travels exclusively in the URL fragment (never sent here).
 */
router.post(
  '/upload',
  upload.single('file'),
  validateUploadMetadata,
  async (req, res, next) => {
    try {
      const {
        iv,
        salt,
        originalName,
        mimetype,
        expiresIn,
        maxDownloads,
      } = req.body;

      if (!req.file?.buffer) {
        return res.status(400).json({ error: 'No encrypted file provided.' });
      }

      // Generate unique identifiers
      const fileId = uuidv4();
      const s3Key  = `encrypted/${fileId}`;   // stored in S3 under this path

      // Calculate expiry timestamp
      let expiresAt = null;
      const expSec  = parseInt(expiresIn, 10) || 0;
      if (expSec > 0) {
        const expDate = new Date(Date.now() + expSec * 1000);
        expiresAt     = expDate.toISOString().replace('T', ' ').slice(0, 19);
      }

      const maxDL = parseInt(maxDownloads, 10) || null;

      // 1. Upload the encrypted blob to S3/MinIO
      await uploadEncryptedBlob(s3Key, req.file.buffer, req.file.size);

      // 2. Store metadata in the database (NO key, NO plaintext)
      insertFile.run({
        id:                fileId,
        s3_key:            s3Key,
        original_filename: originalName || 'download',
        mimetype:          mimetype     || 'application/octet-stream',
        iv,
        salt,
        expires_at:        expiresAt,
        max_downloads:     maxDL,
        file_size_bytes:   req.file.size,
      });

      console.log(`[UPLOAD] File ${fileId} stored. Expires: ${expiresAt || 'never'}. Max DL: ${maxDL || '∞'}`);

      res.status(201).json({
        fileId,
        message: 'Encrypted file stored. Share the link — the server has no key.',
      });

    } catch (err) {
      next(err);
    }
  }
);

// ─── GET /api/files/:id/meta ──────────────────────────────────────────────────

/**
 * Returns metadata needed for the download UI:
 *  - filename, mimetype (to show the user what they're downloading)
 *  - IV and salt (needed by the crypto engine to reconstruct the AES key)
 *  - expiry info (for display)
 *
 * SECURITY: IV and salt are not secrets. They are random, per-file,
 * and are useless without the key (which is only in the URL fragment).
 * Sending them over the network is safe and standard practice.
 */
router.get('/:id/meta', async (req, res, next) => {
  try {
    const file = getFileById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'File not found or has expired.' });
    }

    res.json({
      filename:      file.original_filename,
      mimetype:      file.mimetype,
      iv:            file.iv,
      salt:          file.salt,
      expiresAt:     file.expires_at,
      maxDownloads:  file.max_downloads,
      downloadCount: file.download_count,
      fileSizeBytes: file.file_size_bytes,
    });
  } catch (err) {
    next(err);
  }
});

// ─── GET /api/files/:id ───────────────────────────────────────────────────────

/**
 * Stream the encrypted blob to the client.
 *
 * FLOW:
 * 1. Verify file exists and hasn't expired
 * 2. Increment download counter (atomic)
 * 3. If this was the last allowed download → delete after streaming
 * 4. Stream encrypted blob
 *
 * The client (browser JS) will decrypt it using the key from the URL hash.
 *
 * SECURITY: We send Content-Disposition: attachment so the browser
 * doesn't try to "open" or parse the raw ciphertext.
 */
router.get('/:id', async (req, res, next) => {
  try {
    const file = getFileById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'File not found or has expired.' });
    }

    // Verify the object still exists in S3
    const exists = await objectExists(file.s3_key);
    if (!exists) {
      deleteFile.run(file.id); // clean up dangling DB record
      return res.status(404).json({ error: 'File not found in storage.' });
    }

    // Increment download count
    const newCount = incrementDownload(file.id);

    // Check if this download triggers burn-after-reading
    const isBurnDownload =
      file.max_downloads !== null && newCount >= file.max_downloads;

    // Set headers
    res.setHeader('Content-Type',        'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="encrypted_blob"`);
    res.setHeader('Content-Length',      file.file_size_bytes);
    // Prevent caching of the encrypted payload
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma',        'no-cache');

    // Stream the encrypted blob
    const { stream } = await streamEncryptedBlob(file.s3_key);
    stream.pipe(res);

    // After streaming completes, delete if burn-after-reading triggered
    stream.on('end', async () => {
      if (isBurnDownload) {
        console.log(`[BURN] Deleting file ${file.id} — download limit reached.`);
        await deleteBlob(file.s3_key).catch(console.error);
        deleteFile.run(file.id);
      }
    });

    stream.on('error', (err) => {
      console.error(`[STREAM ERROR] ${file.id}:`, err);
    });

  } catch (err) {
    next(err);
  }
});

// ─── DELETE /api/files/:id ────────────────────────────────────────────────────

/**
 * Immediately delete a file (uploader-initiated).
 * In a real system, you'd require a deletion token stored in localStorage
 * at upload time. Here we demonstrate the pattern.
 */
router.delete('/:id', async (req, res, next) => {
  try {
    const { deleteToken } = req.body;

    const file = getFileById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'File not found.' });
    }

    // In production: validate deleteToken against a stored hash
    // For simplicity, we allow any delete request here
    if (process.env.REQUIRE_DELETE_TOKEN === 'true' && !deleteToken) {
      return res.status(403).json({ error: 'Delete token required.' });
    }

    await deleteBlob(file.s3_key);
    deleteFile.run(file.id);

    console.log(`[DELETE] File ${file.id} manually deleted.`);
    res.json({ message: 'File permanently deleted.' });
  } catch (err) {
    next(err);
  }
});

export default router;
