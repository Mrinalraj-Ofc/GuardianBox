/**
 * db.js — GuardianBox Database Layer
 * ────────────────────────────────────
 * Uses SQLite (better-sqlite3) for simplicity.
 * Swap with PostgreSQL/MySQL for production scale.
 *
 * ZERO-KNOWLEDGE SCHEMA:
 *  The database stores ONLY:
 *   - A random file ID (UUID)
 *   - The S3 object key (pointer to encrypted blob)
 *   - The original filename (encrypted or hashed — you decide)
 *   - The MIME type (needed for browser download trigger)
 *   - The IV (needed for decryption — NOT the key)
 *   - The salt (needed for PBKDF2 re-derivation — NOT the password)
 *   - Expiration metadata (time-based or download-count-based)
 *
 *  NEVER stored: passwords, keys, plaintext file content.
 *  If this database is stolen, the attacker gets useless metadata.
 */

import Database from 'better-sqlite3';
import path     from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH   = process.env.DB_PATH || path.join(__dirname, 'guardianbox.db');

export const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

// Enable foreign key enforcement
db.pragma('foreign_keys = ON');

// ─── Schema Migration ─────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id                TEXT PRIMARY KEY,          -- UUID v4
    s3_key            TEXT NOT NULL UNIQUE,      -- S3 / MinIO object key
    original_filename TEXT NOT NULL,             -- original file name for download
    mimetype          TEXT NOT NULL DEFAULT 'application/octet-stream',
    
    -- Cryptographic metadata (NOT secrets — only helpers for decryption)
    -- The IV is stored here because it's needed to decrypt but is NOT the key.
    -- Without the key (in the URL fragment), IV alone is useless.
    iv                TEXT NOT NULL,             -- base64url AES-GCM IV (12 bytes)
    salt              TEXT NOT NULL,             -- base64url PBKDF2 salt (16 bytes)
    
    -- Expiration (ephemeral storage)
    expires_at        DATETIME,                  -- NULL = never expires
    max_downloads     INTEGER DEFAULT NULL,      -- NULL = unlimited downloads
    download_count    INTEGER NOT NULL DEFAULT 0,
    
    -- Audit
    created_at        DATETIME NOT NULL DEFAULT (datetime('now')),
    file_size_bytes   INTEGER NOT NULL DEFAULT 0
  );

  -- Index for efficient expiration queries (cron job uses this)
  CREATE INDEX IF NOT EXISTS idx_files_expires_at
    ON files(expires_at)
    WHERE expires_at IS NOT NULL;

  -- Index for download-count-based expiration
  CREATE INDEX IF NOT EXISTS idx_files_downloads
    ON files(download_count, max_downloads)
    WHERE max_downloads IS NOT NULL;
`);

// ─── Repository Functions ─────────────────────────────────────────────────────

/**
 * Insert a new file record after upload.
 */
export const insertFile = db.prepare(`
  INSERT INTO files (id, s3_key, original_filename, mimetype, iv, salt, expires_at, max_downloads, file_size_bytes)
  VALUES (@id, @s3_key, @original_filename, @mimetype, @iv, @salt, @expires_at, @max_downloads, @file_size_bytes)
`);

/**
 * Retrieve a file record by ID.
 * Returns null if not found or expired.
 */
export function getFileById(id) {
  const row = db.prepare(`
    SELECT * FROM files
    WHERE id = ?
      AND (expires_at IS NULL OR expires_at > datetime('now'))
      AND (max_downloads IS NULL OR download_count < max_downloads)
  `).get(id);
  return row || null;
}

/**
 * Increment the download counter atomically.
 * Returns the updated download count.
 */
export function incrementDownload(id) {
  const stmt = db.prepare(`
    UPDATE files
    SET download_count = download_count + 1
    WHERE id = ?
    RETURNING download_count
  `);
  const row = stmt.get(id);
  return row?.download_count ?? 0;
}

/**
 * Delete a file record (after S3 object is also deleted).
 */
export const deleteFile = db.prepare(`
  DELETE FROM files WHERE id = ?
`);

/**
 * Return all expired file records for cleanup.
 * Called by the cron job.
 */
export function getExpiredFiles() {
  return db.prepare(`
    SELECT id, s3_key FROM files
    WHERE
      (expires_at IS NOT NULL AND expires_at <= datetime('now'))
      OR
      (max_downloads IS NOT NULL AND download_count >= max_downloads)
  `).all();
}

/**
 * Return storage statistics (admin use).
 * NEVER returns file content or crypto material.
 */
export function getStats() {
  return db.prepare(`
    SELECT
      COUNT(*)               AS total_files,
      SUM(file_size_bytes)   AS total_bytes,
      SUM(download_count)    AS total_downloads
    FROM files
  `).get();
}
