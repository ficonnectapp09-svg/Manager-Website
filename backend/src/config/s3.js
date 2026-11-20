/**
 * Storage Adapter — Cloudinary-only implementation
 *
 * AWS S3 has been fully removed. All uploads, URL resolution, and media
 * streaming are handled exclusively by Cloudinary, configured via environment
 * variables in the backend .env file.
 *
 * Required environment variables (set in backend .env):
 *   CLOUDINARY_URL=cloudinary://<api_key>:<api_secret>@<cloud_name>
 *   — OR —
 *   CLOUDINARY_CLOUD_NAME=<cloud_name>
 *   CLOUDINARY_API_KEY=<api_key>
 *   CLOUDINARY_API_SECRET=<api_secret>
 *
 * This module re-exports the Cloudinary upload function as `uploadToS3` for
 * backward compatibility — no changes required in any calling controller or route.
 */

const {
  cloudinary,
  uploadToCloudinary,
  deleteFromCloudinary,
  isCloudinaryConfigured,
  extractPublicId
} = require('./cloudinary');

// ─── Startup configuration guard ───────────────────────────────────────────
if (!isCloudinaryConfigured()) {
  console.error(
    '[Storage] CONFIGURATION ERROR: Cloudinary is not configured.\n' +
    '  Set CLOUDINARY_URL=cloudinary://<api_key>:<api_secret>@<cloud_name>\n' +
    '  or set CLOUDINARY_CLOUD_NAME + CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET\n' +
    '  in the backend .env file before starting the server.'
  );
}

// ─── uploadToS3 — backward-compatible alias for uploadToCloudinary ──────────
/**
 * Uploads a file (Buffer, local path, or base64 Data URI) to Cloudinary.
 * Drop-in replacement for the removed AWS S3 uploadToS3 function.
 * Returns the same response shape: { success, url, secure_url, key, publicId, ... }
 *
 * @param {Buffer|string} fileBufferOrPath - File Buffer, local path, or data: URI
 * @param {string} folder - Destination folder (e.g. 'manager_avatars', 'voice_notes')
 * @param {string} filenameHint - Original filename for naming and format detection
 * @returns {Promise<Object>} Standardised upload result with Cloudinary HTTPS URL
 */
async function uploadToS3(fileBufferOrPath, folder = 'manager_uploads', filenameHint = 'upload.jpg') {
  if (!isCloudinaryConfigured()) {
    throw new Error(
      'Storage is not configured. Set CLOUDINARY_URL (or CLOUDINARY_CLOUD_NAME + ' +
      'CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET) in the backend .env file.'
    );
  }
  return uploadToCloudinary(fileBufferOrPath, folder, filenameHint);
}

// ─── getDurableImageUrl — returns Cloudinary URL directly ──────────────────
/**
 * Returns a durable, publicly accessible URL for the given Cloudinary public ID or URL.
 * For Cloudinary, the secure_url returned by the uploader is already durable.
 *
 * @param {string} publicIdOrUrl - Cloudinary public ID or existing Cloudinary URL
 * @returns {string} Cloudinary HTTPS URL
 */
function getDurableImageUrl(publicIdOrUrl) {
  if (!publicIdOrUrl) return '';
  const trimmed = String(publicIdOrUrl).trim();
  if (trimmed.startsWith('https://res.cloudinary.com/') || trimmed.startsWith('http://res.cloudinary.com/')) {
    return trimmed.replace('http://', 'https://');
  }
  // If it looks like a Cloudinary public ID, build the URL
  if (trimmed && !trimmed.startsWith('http')) {
    try {
      const cloudName = process.env.CLOUDINARY_CLOUD_NAME ||
        (process.env.CLOUDINARY_URL && process.env.CLOUDINARY_URL.split('@')[1]) || '';
      if (cloudName) {
        return `https://res.cloudinary.com/${cloudName}/image/upload/${trimmed}`;
      }
    } catch {}
  }
  return trimmed;
}

// ─── resolveDurableImageUrl — normalises any stored URL ───────────────────
/**
 * Resolves any stored URL/key into a fully-qualified HTTPS URL suitable for display.
 *
 * @param {string} input - Cloudinary URL, relative path, or public ID
 * @returns {string} Resolved HTTPS URL
 */
function resolveDurableImageUrl(input) {
  if (!input || typeof input !== 'string') return '';
  const trimmed = input.trim();
  if (!trimmed || trimmed === 'null' || trimmed === 'undefined') return '';
  if (trimmed.startsWith('https://res.cloudinary.com/')) return trimmed;
  if (trimmed.startsWith('http://res.cloudinary.com/')) return trimmed.replace('http://', 'https://');
  if (trimmed.startsWith('data:') || trimmed.startsWith('blob:')) return trimmed;
  if (trimmed.startsWith('/uploads/') || trimmed.startsWith('uploads/')) return trimmed;
  return getDurableImageUrl(trimmed);
}

// ─── extractS3Key — extracts Cloudinary public ID from URL ─────────────────
/**
 * Extracts the Cloudinary public ID from a Cloudinary URL.
 * Named extractS3Key for backward compatibility.
 *
 * @param {string} urlOrKey - Cloudinary URL or public ID
 * @returns {string|null} Cloudinary public ID, or null if not extractable
 */
function extractS3Key(urlOrKey) {
  if (!urlOrKey || typeof urlOrKey !== 'string') return null;
  return extractPublicId(urlOrKey);
}

// ─── getPresignedUrl — Cloudinary URLs are direct HTTPS; no presigning needed
/**
 * Returns the Cloudinary URL directly.
 * Cloudinary CDN URLs are publicly accessible HTTPS URLs — no presigning required.
 *
 * @param {string} keyOrUrl - Cloudinary public ID or URL
 * @returns {Promise<string>} Cloudinary HTTPS URL
 */
async function getPresignedUrl(keyOrUrl) {
  if (!keyOrUrl) return '';
  return getDurableImageUrl(keyOrUrl);
}

// ─── getObjectStream — not applicable for Cloudinary ─────────────────────
/**
 * Not applicable for Cloudinary (CDN URLs are served directly).
 * Returns a failure result so callers that check .success can handle gracefully.
 */
async function getObjectStream(_key) {
  return {
    success: false,
    error: 'Direct S3 object streaming is not supported. Media is served via Cloudinary CDN URLs.'
  };
}

// ─── getS3Client — removed; no S3 client exists ───────────────────────────
function getS3Client() {
  throw new Error(
    'AWS S3 has been removed from this project. All storage uses Cloudinary. ' +
    'Configure CLOUDINARY_URL in the backend .env file.'
  );
}

module.exports = {
  // Primary upload function (Cloudinary-backed)
  uploadToS3,
  uploadToCloudinary,
  deleteFromCloudinary,
  isCloudinaryConfigured,

  // URL helpers
  getDurableImageUrl,
  resolveDurableImageUrl,
  extractS3Key,
  extractPublicId,

  // Legacy compatibility stubs
  getPresignedUrl,
  getObjectStream,
  getS3Client
};
