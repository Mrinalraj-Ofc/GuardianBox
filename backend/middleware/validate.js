/**
 * middleware/validate.js — GuardianBox Input Validation
 * ──────────────────────────────────────────────────────
 * Validates upload metadata before storing anything.
 * Prevents malformed data from entering the database.
 */

// Base64url pattern: only alphanumeric, -, _ characters
const BASE64URL_REGEX = /^[A-Za-z0-9\-_]+$/;

/**
 * Validate that a string is a valid base64url-encoded value
 * of an expected decoded byte length.
 *
 * @param {string} value     — the base64url string
 * @param {number} byteLen   — expected decoded byte count
 */
function isValidBase64url(value, byteLen) {
  if (!value || typeof value !== 'string') return false;
  if (!BASE64URL_REGEX.test(value))        return false;

  // Approximate byte length check: base64 encodes 3 bytes as 4 chars
  // URL-safe base64 strips padding → length ≈ ceil(byteLen * 4/3)
  const expectedLen = Math.ceil(byteLen * 4 / 3);
  return value.length >= expectedLen - 2 && value.length <= expectedLen + 2;
}

/**
 * Validates and sanitises the metadata fields sent with an upload.
 * Rejects requests with missing/malformed fields early.
 */
export function validateUploadMetadata(req, res, next) {
  const {
    iv,
    salt,
    originalName,
    mimetype,
    expiresIn,
    maxDownloads,
  } = req.body;

  const errors = [];

  // ── IV: must be valid 12-byte base64url ──────────────────────────────────
  if (!isValidBase64url(iv, 12)) {
    errors.push('iv must be a valid base64url-encoded 12-byte value (AES-GCM nonce).');
  }

  // ── Salt: must be valid 16-byte base64url ────────────────────────────────
  if (!isValidBase64url(salt, 16)) {
    errors.push('salt must be a valid base64url-encoded 16-byte value (PBKDF2 salt).');
  }

  // ── Original filename: must exist and be safe ────────────────────────────
  if (!originalName || typeof originalName !== 'string') {
    errors.push('originalName is required.');
  } else if (originalName.length > 255) {
    errors.push('originalName must be 255 characters or fewer.');
  } else if (/[<>:"/\\|?*\x00-\x1f]/.test(originalName)) {
    errors.push('originalName contains invalid characters.');
  }

  // ── MIME type: basic format check ────────────────────────────────────────
  if (mimetype && typeof mimetype === 'string') {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_]{0,30}\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_.+]{0,100}$/.test(mimetype)) {
      errors.push('mimetype format is invalid.');
    }
  }

  // ── Expiry: must be a non-negative number ────────────────────────────────
  if (expiresIn !== undefined && expiresIn !== '') {
    const exp = parseInt(expiresIn, 10);
    if (isNaN(exp) || exp < 0) {
      errors.push('expiresIn must be a non-negative integer (seconds).');
    }
    if (exp > 30 * 24 * 60 * 60) { // 30 days max
      errors.push('expiresIn cannot exceed 30 days (2592000 seconds).');
    }
  }

  // ── Max Downloads: must be a positive integer or 0 ───────────────────────
  if (maxDownloads !== undefined && maxDownloads !== '') {
    const maxDL = parseInt(maxDownloads, 10);
    if (isNaN(maxDL) || maxDL < 0) {
      errors.push('maxDownloads must be a non-negative integer.');
    }
    if (maxDL > 1000) {
      errors.push('maxDownloads cannot exceed 1000.');
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({
      error:   'Validation failed.',
      details: errors,
    });
  }

  next();
}
