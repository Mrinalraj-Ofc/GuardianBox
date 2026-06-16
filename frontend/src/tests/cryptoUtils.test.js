/**
 * cryptoUtils.test.js — GuardianBox Crypto Unit Tests
 * ────────────────────────────────────────────────────
 * Run with:  npx vitest run
 *
 * Tests the fundamental security invariant:
 *   encrypt(data, key) |> decrypt(ciphertext, key) === data
 *
 * Also tests tamper-detection, wrong-key rejection, and URL helpers.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  encryptFile,
  decryptFile,
  bufferToBase64,
  base64ToBuffer,
  buildShareURL,
  parseURLFragment,
  generateAutoKey,
  importAutoKey,
} from './cryptoUtils.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Create a synthetic File object from a string payload.
 */
function makeFile(content, name = 'test.txt', type = 'text/plain') {
  return new File([content], name, { type });
}

/**
 * Pack an encrypted result's blob back into an ArrayBuffer for decryption.
 */
async function blobToBuffer(blob) {
  return blob.arrayBuffer();
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('cryptoUtils — Auto-Key Mode', () => {

  it('round-trips correctly: encrypt → decrypt returns original data', async () => {
    const original = 'Top secret document for journalists only 🔐';
    const file     = makeFile(original);
    const result   = await encryptFile(file, { mode: 'auto' });

    expect(result.encryptedBlob).toBeDefined();
    expect(result.keyB64).toBeDefined();        // key must be present for URL
    expect(result.filename).toBe('test.txt');
    expect(result.mimetype).toBe('text/plain');

    const buffer = await blobToBuffer(result.encryptedBlob);
    const dec    = await decryptFile(buffer, {
      mode:   'auto',
      keyB64: result.keyB64,
    });

    const text = new TextDecoder().decode(dec);
    expect(text).toBe(original);
  });

  it('produces different ciphertext on every call (random IV)', async () => {
    const file      = makeFile('same content');
    const result1   = await encryptFile(file, { mode: 'auto' });
    const result1b  = makeFile('same content'); // fresh File object
    const result2   = await encryptFile(result1b, { mode: 'auto' });

    // IVs are random → ciphertexts must differ even for identical plaintext
    expect(result1.iv).not.toBe(result2.iv);
  });

  it('rejects decryption with wrong key', async () => {
    const file   = makeFile('classified information');
    const result = await encryptFile(file, { mode: 'auto' });
    const buffer = await blobToBuffer(result.encryptedBlob);

    // Generate a completely different key
    const { keyB64: wrongKey } = await generateAutoKey();

    await expect(
      decryptFile(buffer, { mode: 'auto', keyB64: wrongKey })
    ).rejects.toThrow('Decryption failed');
  });

  it('detects ciphertext tampering (GCM integrity check)', async () => {
    const file   = makeFile('tamper me');
    const result = await encryptFile(file, { mode: 'auto' });
    const buffer = await blobToBuffer(result.encryptedBlob);

    // Flip a byte in the ciphertext section (after salt+iv = 28 bytes)
    const tampered  = new Uint8Array(buffer);
    tampered[50]    ^= 0xFF;           // bit-flip

    await expect(
      decryptFile(tampered.buffer, { mode: 'auto', keyB64: result.keyB64 })
    ).rejects.toThrow('Decryption failed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('cryptoUtils — Password Mode', () => {

  it('round-trips correctly with a user password', async () => {
    const original = '{"secret": "my private key 🗝️"}';
    const password = 'My$3cureP@ss!';
    const file     = makeFile(original, 'data.json', 'application/json');
    const result   = await encryptFile(file, { mode: 'password', password });

    // In password mode, no keyB64 — the password IS the secret
    expect(result.keyB64).toBeUndefined();

    const buffer = await blobToBuffer(result.encryptedBlob);
    const dec    = await decryptFile(buffer, { mode: 'password', password });
    const text   = new TextDecoder().decode(dec);
    expect(text).toBe(original);
  });

  it('fails decryption with wrong password', async () => {
    const file   = makeFile('secret data');
    const result = await encryptFile(file, { mode: 'password', password: 'correct' });
    const buffer = await blobToBuffer(result.encryptedBlob);

    await expect(
      decryptFile(buffer, { mode: 'password', password: 'wrong-password' })
    ).rejects.toThrow('Decryption failed');
  });

  it('throws when password is missing', async () => {
    const file = makeFile('data');
    await expect(
      encryptFile(file, { mode: 'password' })
    ).rejects.toThrow('Password is required');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('cryptoUtils — Binary File Handling', () => {

  it('encrypts and decrypts a binary file correctly', async () => {
    // Simulate a PNG-like binary payload
    const original  = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const file      = new File([original], 'image.png', { type: 'image/png' });
    const result    = await encryptFile(file, { mode: 'auto' });
    const buffer    = await blobToBuffer(result.encryptedBlob);
    const dec       = await decryptFile(buffer, { mode: 'auto', keyB64: result.keyB64 });
    const decBytes  = new Uint8Array(dec);

    expect(Array.from(decBytes)).toEqual(Array.from(original));
  });

  it('preserves filename and mimetype in result', async () => {
    const file   = new File(['data'], 'report.pdf', { type: 'application/pdf' });
    const result = await encryptFile(file, { mode: 'auto' });
    expect(result.filename).toBe('report.pdf');
    expect(result.mimetype).toBe('application/pdf');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('cryptoUtils — Base64 Encoding', () => {

  it('round-trips bufferToBase64 → base64ToBuffer', () => {
    const original  = new Uint8Array([0, 1, 2, 255, 128, 64]);
    const b64       = bufferToBase64(original);
    const restored  = new Uint8Array(base64ToBuffer(b64));
    expect(Array.from(restored)).toEqual(Array.from(original));
  });

  it('produces URL-safe Base64 (no + / = characters)', () => {
    // Test multiple random-ish arrays to catch edge cases
    for (let i = 0; i < 20; i++) {
      const bytes = new Uint8Array(32).map(() => Math.floor(Math.random() * 256));
      const b64   = bufferToBase64(bytes);
      expect(b64).not.toMatch(/[+/=]/);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('cryptoUtils — URL Fragment Helpers', () => {

  it('buildShareURL embeds mode and secret in fragment', () => {
    // Mock window.location.origin
    Object.defineProperty(window, 'location', {
      value: { origin: 'https://guardianbox.app' },
      writable: true,
    });

    const url = buildShareURL('file-abc-123', { mode: 'auto', secret: 'myKey' });
    expect(url).toBe('https://guardianbox.app/file/file-abc-123#auto:myKey');
  });

  it('parseURLFragment correctly parses auto mode', () => {
    const result = parseURLFragment('#auto:XYZ123abc');
    expect(result).toEqual({ mode: 'auto', secret: 'XYZ123abc' });
  });

  it('parseURLFragment correctly parses password mode', () => {
    const result = parseURLFragment('#password:MyP@ss:w0rd');
    expect(result).toEqual({ mode: 'password', secret: 'MyP@ss:w0rd' });
  });

  it('parseURLFragment returns null for empty fragment', () => {
    expect(parseURLFragment('')).toBeNull();
    expect(parseURLFragment('#')).toBeNull();
  });

  it('URL fragment is NEVER part of HTTP request (security assertion)', () => {
    // This is a browser-spec assertion. We verify our URL structure.
    const url = buildShareURL('xyz', { mode: 'auto', secret: 'SECRET_KEY' });
    const urlObj     = new URL(url);
    const serverPath = urlObj.pathname;      // what the server sees
    const clientHash = urlObj.hash;          // what stays in browser

    expect(serverPath).toBe('/file/xyz');    // no secret here
    expect(clientHash).toContain('SECRET_KEY'); // secret is only in hash
    expect(serverPath).not.toContain('SECRET_KEY');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('cryptoUtils — Zero-Knowledge Security Invariants', () => {

  it('encrypted blob contains no plaintext traces', async () => {
    const secret = 'TOP SECRET NUCLEAR CODES';
    const file   = makeFile(secret);
    const result = await encryptFile(file, { mode: 'auto' });
    const buffer = await blobToBuffer(result.encryptedBlob);

    // The ciphertext should not contain the plaintext string as UTF-8
    const asText = new TextDecoder('utf-8', { fatal: false }).decode(buffer);
    expect(asText).not.toContain('TOP SECRET');
    expect(asText).not.toContain('NUCLEAR');
  });

  it('same plaintext with different runs produces different ciphertext (IND-CPA)', async () => {
    const content = 'indistinguishability test';
    const f1      = makeFile(content);
    const f2      = makeFile(content);

    const r1 = await encryptFile(f1, { mode: 'auto' });
    const r2 = await encryptFile(f2, { mode: 'auto' });

    const b1 = bufferToBase64(await blobToBuffer(r1.encryptedBlob));
    const b2 = bufferToBase64(await blobToBuffer(r2.encryptedBlob));

    // Different keys AND different IVs — ciphertexts must differ
    expect(b1).not.toBe(b2);
  });
});
