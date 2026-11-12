const cloudinary = require('cloudinary').v2;
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Readable } = require('stream');
const dotenv = require('dotenv');

// Ensure environment variables are loaded from available .env paths
const candidateEnvPaths = [
  path.join(__dirname, '..', '..', '.env'),
  path.join(__dirname, '..', '..', '..', '.env'),
  path.join(process.cwd(), '.env'),
  path.join(process.cwd(), 'backend', '.env')
];
candidateEnvPaths.forEach(p => {
  if (fs.existsSync(p)) {
    dotenv.config({ path: p });
  }
});

const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
const apiKey = process.env.CLOUDINARY_API_KEY;
const apiSecret = process.env.CLOUDINARY_API_SECRET;
const cloudinaryUrl = process.env.CLOUDINARY_URL;

if (cloudinaryUrl) {
  cloudinary.config(cloudinaryUrl);
} else if (cloudName && apiKey && apiSecret) {
  cloudinary.config({
    cloud_name: cloudName,
    api_key: apiKey,
    api_secret: apiSecret,
    secure: true
  });
}

function isCloudinaryConfigured() {
  return Boolean(process.env.CLOUDINARY_URL || (cloudName && apiKey && apiSecret));
}

function extractPublicId(urlOrId) {
  if (!urlOrId || typeof urlOrId !== 'string') return null;
  const trimmed = urlOrId.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    const parts = parsed.pathname.split('/upload/');
    if (parts.length > 1) {
      let pathAfterUpload = parts[1];
      // Strip version prefix if present, e.g. v1234567890/
      pathAfterUpload = pathAfterUpload.replace(/^v\d+\//, '');
      // Strip extension
      const lastDot = pathAfterUpload.lastIndexOf('.');
      return lastDot !== -1 ? pathAfterUpload.substring(0, lastDot) : pathAfterUpload;
    }
  } catch {}
  return null;
}

/**
 * Uploads a file (Buffer, local file path, or base64 Data URI) to Cloudinary.
 * Supports images, videos, audio, and documents (PDF, DOCX, CSV, etc.) with automatic resource detection.
 *
 * @param {Buffer|string} fileBufferOrPath - The file Buffer, local file path, or data URI to upload.
 * @param {string} folder - Destination folder on Cloudinary (e.g. 'manager_docs', 'shop_visits').
 * @param {string} filenameHint - Original filename or hint for naming and format detection.
 * @returns {Promise<Object>} Standardized upload result with HTTPS URL and public ID.
 */
async function uploadToCloudinary(fileBufferOrPath, folder = 'manager_uploads', filenameHint = 'upload.jpg') {
  if (!fileBufferOrPath) {
    throw new Error('No file provided for upload.');
  }

  // If already an absolute Cloudinary URL, return as-is
  if (typeof fileBufferOrPath === 'string') {
    const trimmed = fileBufferOrPath.trim();
    if (trimmed.startsWith('https://res.cloudinary.com/') || trimmed.startsWith('http://res.cloudinary.com/')) {
      const secureUrl = trimmed.startsWith('http://') ? trimmed.replace('http://', 'https://') : trimmed;
      const pid = extractPublicId(secureUrl) || secureUrl;
      return {
        success: true,
        url: secureUrl,
        secure_url: secureUrl,
        key: pid,
        publicId: pid,
        public_id: pid,
        toString() { return secureUrl; },
        [Symbol.toPrimitive]() { return secureUrl; }
      };
    }
  }

  const safeFolder = `connect_manager/${String(folder || 'manager_uploads').replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  const baseName = path.parse(filenameHint || 'upload').name.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50);
  const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const publicId = `${baseName}_${uniqueSuffix}`;

  const uploadOptions = {
    folder: safeFolder,
    public_id: publicId,
    resource_type: 'auto',
    overwrite: true,
    unique_filename: true,
    use_filename: false
  };

  // Case 1: Buffer input
  if (Buffer.isBuffer(fileBufferOrPath)) {
    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(uploadOptions, (error, result) => {
        if (error) {
          console.error('[Cloudinary Upload Stream Error]:', error);
          return reject(error);
        }
        const secureUrl = result.secure_url || result.url;
        resolve({
          success: true,
          url: secureUrl,
          secure_url: secureUrl,
          key: result.public_id,
          publicId: result.public_id,
          public_id: result.public_id,
          category: result.resource_type,
          resourceType: result.resource_type,
          format: result.format,
          extension: result.format,
          size: result.bytes,
          bytes: result.bytes,
          width: result.width,
          height: result.height,
          toString() { return secureUrl; },
          [Symbol.toPrimitive]() { return secureUrl; }
        });
      });

      Readable.from(fileBufferOrPath).pipe(uploadStream);
    });
  }

  // Case 2: String input (base64 Data URI or local file path)
  if (typeof fileBufferOrPath === 'string') {
    const trimmed = fileBufferOrPath.trim();

    // Data URI or local file path
    if (trimmed.startsWith('data:') || fs.existsSync(trimmed)) {
      const result = await cloudinary.uploader.upload(trimmed, uploadOptions);
      const secureUrl = result.secure_url || result.url;
      return {
        success: true,
        url: secureUrl,
        secure_url: secureUrl,
        key: result.public_id,
        publicId: result.public_id,
        public_id: result.public_id,
        category: result.resource_type,
        resourceType: result.resource_type,
        format: result.format,
        extension: result.format,
        size: result.bytes,
        bytes: result.bytes,
        width: result.width,
        height: result.height,
        toString() { return secureUrl; },
        [Symbol.toPrimitive]() { return secureUrl; }
      };
    }

    throw new Error('Invalid file string provided for Cloudinary upload (expected file path or data URI).');
  }

  throw new Error('Unsupported file format for Cloudinary upload (expected Buffer or string).');
}

/**
 * Removes a file from Cloudinary by public ID or URL.
 */
async function deleteFromCloudinary(publicIdOrUrl, resourceType = 'image') {
  if (!publicIdOrUrl) return { success: false, message: 'No target provided' };
  const pid = extractPublicId(publicIdOrUrl);
  if (!pid) return { success: false, message: 'Could not extract public ID' };

  try {
    const res = await cloudinary.uploader.destroy(pid, { resource_type: resourceType });
    return { success: res.result === 'ok', result: res.result };
  } catch (err) {
    console.warn('[Cloudinary Delete Warning]:', err.message);
    return { success: false, error: err.message };
  }
}

module.exports = {
  cloudinary,
  uploadToCloudinary,
  deleteFromCloudinary,
  isCloudinaryConfigured,
  extractPublicId
};

