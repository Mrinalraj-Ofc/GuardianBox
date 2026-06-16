/**
 * storage.js — GuardianBox S3 / MinIO Object Storage Adapter
 * ──────────────────────────────────────────────────────────
 * This module handles all communication with object storage.
 * It only ever deals with ENCRYPTED blobs — never plaintext.
 *
 * Works with:
 *  • AWS S3 (set STORAGE_PROVIDER=s3)
 *  • MinIO self-hosted (set STORAGE_PROVIDER=minio, default)
 */

import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Readable } from 'stream';

// ─── Client Configuration ─────────────────────────────────────────────────────

const PROVIDER = process.env.STORAGE_PROVIDER || 'minio';
const BUCKET   = process.env.S3_BUCKET        || 'guardianbox-encrypted';

/**
 * Build the S3 client. For MinIO, we override the endpoint.
 * For AWS S3, just region + credentials via environment.
 */
function createClient() {
  const baseConfig = {
    region:      process.env.AWS_REGION || 'us-east-1',
    credentials: {
      accessKeyId:     process.env.AWS_ACCESS_KEY_ID     || 'minioadmin',
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'minioadmin',
    },
  };

  if (PROVIDER === 'minio') {
    return new S3Client({
      ...baseConfig,
      endpoint:          process.env.MINIO_ENDPOINT || 'http://127.0.0.1:9000',
      forcePathStyle:    true,   // required for MinIO
      tls:               false,
    });
  }

  // AWS S3 — use default SDK resolution
  return new S3Client(baseConfig);
}

export const s3 = createClient();

// ─── Storage Operations ───────────────────────────────────────────────────────

/**
 * Upload an encrypted blob to S3 / MinIO.
 *
 * IMPORTANT: This function receives only ciphertext. It has no knowledge
 * of the original file content. The blob is treated as opaque binary.
 *
 * @param {string}         s3Key         — unique object key (UUID-based)
 * @param {Buffer|Uint8Array} encryptedBuffer — the full packed payload
 * @param {number}         sizeBytes     — file size for Content-Length
 * @returns {Promise<void>}
 */
export async function uploadEncryptedBlob(s3Key, encryptedBuffer, sizeBytes) {
  const command = new PutObjectCommand({
    Bucket:        BUCKET,
    Key:           s3Key,
    Body:          encryptedBuffer,
    ContentLength: sizeBytes,
    ContentType:   'application/octet-stream',  // always — never the original MIME
    // Server-side encryption at rest (belt AND suspenders)
    ServerSideEncryption: PROVIDER === 's3' ? 'AES256' : undefined,
    // Prevent public access
    ACL: 'private',
    // Tag for lifecycle rules
    Tagging: 'project=guardianbox&encrypted=true',
  });

  await s3.send(command);
  console.log(`[S3] Uploaded encrypted blob: ${s3Key} (${sizeBytes} bytes)`);
}

/**
 * Stream an encrypted blob from S3 / MinIO back to the client.
 * Returns a Node.js Readable stream.
 *
 * @param {string} s3Key
 * @returns {Promise<{ stream: Readable, contentLength: number }>}
 */
export async function streamEncryptedBlob(s3Key) {
  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key:    s3Key,
  });

  const response = await s3.send(command);
  return {
    stream:        response.Body,
    contentLength: response.ContentLength || 0,
  };
}

/**
 * Get metadata of an object without downloading it.
 * Used to verify existence before serving a download.
 *
 * @param {string} s3Key
 * @returns {Promise<boolean>} true if exists
 */
export async function objectExists(s3Key) {
  try {
    await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: s3Key }));
    return true;
  } catch (err) {
    if (err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) {
      return false;
    }
    throw err;
  }
}

/**
 * Permanently delete an encrypted blob from object storage.
 * Called by:
 *  • The cron job (time-based expiration)
 *  • The download handler (burn-after-reading — N views exceeded)
 *  • Explicit user delete requests (if implemented)
 *
 * @param {string} s3Key
 * @returns {Promise<void>}
 */
export async function deleteBlob(s3Key) {
  await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: s3Key }));
  console.log(`[S3] Deleted blob: ${s3Key}`);
}

/**
 * Generate a pre-signed download URL (optional alternative to streaming).
 * Expires in 5 minutes — enough time for the browser to start downloading.
 *
 * NOTE: We DON'T use pre-signed URLs as the default because they can be
 * cached/logged by CDN layers. Streaming through the Express server gives
 * us full control over access logic (download counting, expiration checks).
 *
 * @param {string} s3Key
 * @param {number} expiresIn — seconds (default 300)
 * @returns {Promise<string>} signed URL
 */
export async function getPresignedUrl(s3Key, expiresIn = 300) {
  const command = new GetObjectCommand({ Bucket: BUCKET, Key: s3Key });
  return getSignedUrl(s3, command, { expiresIn });
}
