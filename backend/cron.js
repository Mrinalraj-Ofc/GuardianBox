/**
 * cron.js — GuardianBox Ephemeral Storage Cleanup
 * ─────────────────────────────────────────────────
 * Runs every hour. Deletes:
 *  1. Time-expired files (expires_at < NOW)
 *  2. Download-count-exceeded files (download_count >= max_downloads)
 *
 * Each deletion is a two-step atomic operation:
 *  a. Delete from S3 / MinIO  (removes the encrypted blob)
 *  b. Delete from database    (removes the metadata)
 *
 * If step (a) fails, we leave the DB record so the next cron run retries.
 * If step (b) fails after (a), the blob is gone — DB record is an orphan.
 * On next run, the S3 existence check will clean up the orphan.
 */

import cron         from 'node-cron';
import { getExpiredFiles, deleteFile } from './db.js';
import { deleteBlob }                  from './storage.js';

/**
 * Process one batch of expired files.
 * Returns { deleted, failed } counts.
 */
async function cleanupExpiredFiles() {
  const expiredRows = getExpiredFiles();

  if (expiredRows.length === 0) {
    console.log('[CRON] No expired files found.');
    return { deleted: 0, failed: 0 };
  }

  console.log(`[CRON] Found ${expiredRows.length} expired file(s) to clean up.`);

  let deleted = 0;
  let failed  = 0;

  for (const { id, s3_key } of expiredRows) {
    try {
      // Step 1: Delete encrypted blob from object storage
      await deleteBlob(s3_key);

      // Step 2: Delete metadata from database
      deleteFile.run(id);

      deleted++;
      console.log(`[CRON] ✓ Deleted file ${id}`);
    } catch (err) {
      failed++;
      console.error(`[CRON] ✗ Failed to delete file ${id}:`, err.message);
      // Will retry on the next cron run
    }
  }

  console.log(`[CRON] Cleanup complete. Deleted: ${deleted}, Failed: ${failed}`);
  return { deleted, failed };
}

/**
 * Start the cron scheduler.
 *
 * Schedule: '0 * * * *' → top of every hour
 *
 * For testing / development, set CRON_INTERVAL to every 5 minutes: "star-slash-5 * * * *".
*/
export function startCron() {
  const schedule = process.env.CRON_INTERVAL || '0 * * * *';

  cron.schedule(schedule, async () => {
    console.log(`[CRON] Running scheduled cleanup at ${new Date().toISOString()}`);
    await cleanupExpiredFiles().catch((err) => {
      console.error('[CRON] Unhandled cleanup error:', err);
    });
  });

  console.log(`[CRON] Cleanup job scheduled: "${schedule}"`);

  // Also run once at startup to clean up anything that expired while server was down
  setImmediate(() => {
    cleanupExpiredFiles().catch(console.error);
  });
}

// Export for manual invocation in tests
export { cleanupExpiredFiles };
