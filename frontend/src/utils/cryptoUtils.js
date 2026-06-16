/**
 * cryptoUtils.js — GuardianBox Cryptography Engine
 * ─────────────────────────────────────────────────
 * All encryption / decryption happens here, client-side only.
 * The server NEVER sees plaintext, passwords, or keys.
 *
 * Stack:
 *  • Web Crypto API (browser-native, hardware-accelerated)
 *  • AES-256-GCM  — authenticated encryption (confidentiality + integrity)
 *  • PBKDF2-SHA-256 — key derivation from human passwords (100,000 iterations)
 *  • URL fragment (#) — secret transport (never sent to server by the browser)
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const ALGO        = 'AES-GCM';
const KEY_LENGTH  = 256;          // bits
const IV_LENGTH   = 12;           // bytes — GCM standard nonce size
const SALT_LENGTH = 16;           // bytes — PBKDF2 salt
const ITERATIONS  = 100_000;      // PBKDF2 iteration count (OWASP 2023 minimum)
const HASH        = 'SHA-256';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Encode a Uint8Array / ArrayBuffer to a URL-safe Base64 string */
export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Use URL-safe Base64 (replace + → -, / → _, strip =)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** Decode a URL-safe Base64 string back to an ArrayBuffer */
export function base64ToBuffer(base64) {
  // Restore standard Base64 padding and characters
  const standard = base64.replace(/-/g, '+').replace(/_/g, '/');
  const padded   = standard + '=='.slice(0, (4 - (standard.length % 4)) % 4);
  const binary   = atob(padded);
  const bytes    = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/** Generate cryptographically random bytes */
export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

// ─── Key Derivation ───────────────────────────────────────────────────────────

/**
 * Derive an AES-256-GCM CryptoKey from a human password using PBKDF2.
 * @param {string}     password  — the user's secret phrase
 * @param {Uint8Array} salt      — random 16-byte salt (stored with ciphertext)
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKeyFromPassword(password, salt) {
  const enc          = new TextEncoder();
  const keyMaterial  = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,                       // non-extractable raw material
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name:       'PBKDF2',
      salt,
      iterations: ITERATIONS,
      hash:       HASH,
    },
    keyMaterial,
    { name: ALGO, length: KEY_LENGTH },
    false,                       // derived key is NOT exportable (security)
    ['encrypt', 'decrypt']
  );
}

/**
 * Auto-generate a random AES-256-GCM key (for auto-key mode).
 * The exported key becomes the URL fragment.
 * @returns {Promise<{ key: CryptoKey, keyB64: string }>}
 */
export async function generateAutoKey() {
  const key    = await crypto.subtle.generateKey(
    { name: ALGO, length: KEY_LENGTH },
    true,               // extractable so we can embed in URL hash
    ['encrypt', 'decrypt']
  );
  const raw    = await crypto.subtle.exportKey('raw', key);
  const keyB64 = bufferToBase64(raw);
  return { key, keyB64 };
}

/**
 * Import a raw base64-encoded AES-256-GCM key (from URL fragment).
 * @param {string} keyB64  — base64url key from URL hash
 * @returns {Promise<CryptoKey>}
 */
export async function importAutoKey(keyB64) {
  const raw = base64ToBuffer(keyB64);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: ALGO, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

// ─── Encryption ───────────────────────────────────────────────────────────────

/**
 * Encrypt a File object using AES-256-GCM.
 *
 * Two modes:
 *  • 'auto'     — generates a random key, returns base64 key for URL hash
 *  • 'password' — derives key from password via PBKDF2, returns salt for storage
 *
 * Binary layout of the stored blob:
 *  [salt: 16 bytes] [iv: 12 bytes] [ciphertext: N bytes]
 *
 * @param {File}   file
 * @param {object} options
 * @param {string} options.mode       — 'auto' | 'password'
 * @param {string} [options.password] — required if mode === 'password'
 * @returns {Promise<EncryptionResult>}
 *
 * @typedef {Object} EncryptionResult
 * @property {Blob}   encryptedBlob  — the complete binary payload to upload
 * @property {string} iv             — base64 IV (also embedded in blob)
 * @property {string} salt           — base64 salt (also embedded in blob)
 * @property {string} [keyB64]       — base64 key (only in 'auto' mode)
 * @property {string} filename       — original filename
 * @property {string} mimetype       — original MIME type
 */
export async function encryptFile(file, { mode = 'auto', password } = {}) {
  if (mode === 'password' && !password) {
    throw new Error('Password is required in password mode.');
  }

  const salt = randomBytes(SALT_LENGTH);   // 16 random bytes
  const iv   = randomBytes(IV_LENGTH);     // 12 random bytes (GCM nonce)

  let key, keyB64;
  if (mode === 'auto') {
    ({ key, keyB64 } = await generateAutoKey());
  } else {
    key = await deriveKeyFromPassword(password, salt);
  }

  // Read file into ArrayBuffer
  const fileBuffer  = await file.arrayBuffer();

  // Encrypt — AES-GCM appends a 16-byte authentication tag automatically
  const ciphertext  = await crypto.subtle.encrypt(
    { name: ALGO, iv },
    key,
    fileBuffer
  );

  // Pack: [salt 16B][iv 12B][ciphertext]
  const totalLength = SALT_LENGTH + IV_LENGTH + ciphertext.byteLength;
  const packed      = new Uint8Array(totalLength);
  packed.set(salt,                     0);
  packed.set(iv,                       SALT_LENGTH);
  packed.set(new Uint8Array(ciphertext), SALT_LENGTH + IV_LENGTH);

  return {
    encryptedBlob: new Blob([packed], { type: 'application/octet-stream' }),
    iv:            bufferToBase64(iv),
    salt:          bufferToBase64(salt),
    keyB64,           // undefined in password mode
    filename:      file.name,
    mimetype:      file.type || 'application/octet-stream',
  };
}

// ─── Decryption ───────────────────────────────────────────────────────────────

/**
 * Decrypt an encrypted blob fetched from the server.
 *
 * The blob is the packed binary: [salt 16B][iv 12B][ciphertext]
 * The decryption key is extracted from the URL fragment (#...) by the caller.
 *
 * @param {ArrayBuffer} packedBuffer — raw encrypted payload
 * @param {object}      options
 * @param {string}      options.mode      — 'auto' | 'password'
 * @param {string}      [options.keyB64]  — base64 key from URL hash (auto mode)
 * @param {string}      [options.password]— user-supplied password (password mode)
 * @returns {Promise<ArrayBuffer>} decrypted file bytes
 */
export async function decryptFile(packedBuffer, { mode, keyB64, password }) {
  // Unpack
  const packed = new Uint8Array(packedBuffer);
  const salt   = packed.slice(0, SALT_LENGTH);
  const iv     = packed.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const cipher = packed.slice(SALT_LENGTH + IV_LENGTH).buffer;

  // Reconstruct key
  let key;
  if (mode === 'auto') {
    if (!keyB64) throw new Error('No decryption key found in URL.');
    key = await importAutoKey(keyB64);
  } else {
    if (!password) throw new Error('Password required.');
    key = await deriveKeyFromPassword(password, salt);
  }

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: ALGO, iv },
      key,
      cipher
    );
    return decrypted;
  } catch (err) {
    // GCM authentication tag failure → wrong key / tampered data
    throw new Error(
      'Decryption failed — wrong password/key, or the file has been tampered with.'
    );
  }
}

// ─── Download Trigger ─────────────────────────────────────────────────────────

/**
 * Trigger a browser file download from an ArrayBuffer.
 * @param {ArrayBuffer} buffer
 * @param {string}      filename
 * @param {string}      mimetype
 */
export function triggerDownload(buffer, filename, mimetype) {
  const blob = new Blob([buffer], { type: mimetype });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Revoke object URL after a short delay so download can start
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ─── URL Fragment Helpers ─────────────────────────────────────────────────────

/**
 * Build the shareable URL with the key/password embedded in the fragment.
 * The # fragment is NEVER sent to the server by the browser.
 *
 * Format: https://host/file/FILE_ID#mode:KEY_OR_PASS
 *   e.g.  https://guardianbox.app/file/abc123#auto:Xj9k...
 *
 * @param {string} fileId
 * @param {object} options
 * @param {string} options.mode
 * @param {string} options.secret — keyB64 (auto) or password (password mode)
 * @returns {string} full shareable URL
 */
export function buildShareURL(fileId, { mode, secret }) {
  const base = window.location.origin;
  return `${base}/file/${fileId}#${mode}:${secret}`;
}

/**
 * Parse the URL fragment on the recipient's side.
 * @param {string} hash — window.location.hash (includes the leading #)
 * @returns {{ mode: string, secret: string } | null}
 */
export function parseURLFragment(hash) {
  if (!hash || hash.length < 2) return null;
  const fragment = hash.startsWith('#') ? hash.slice(1) : hash;
  const colonIdx = fragment.indexOf(':');
  if (colonIdx < 0) return null;
  return {
    mode:   fragment.slice(0, colonIdx),
    secret: fragment.slice(colonIdx + 1),
  };
}
