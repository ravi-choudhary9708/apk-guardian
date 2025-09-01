// libs/apkParser.js
import ApkReader from "node-apk-parser";

/**
 * Parse APK directly from a Buffer (no filesystem needed).
 * @param {Buffer} buffer - APK file buffer
 * @returns {Promise<Object>} - Parsed manifest data
 */
export async function parseApkFromBuffer(buffer) {
  return new Promise((resolve, reject) => {
    try {
      const reader = ApkReader.readBuffer(buffer);
      const manifest = reader.readManifestSync();
      resolve(manifest);
    } catch (err) {
      reject(err);
    }
  });
}
