// libs/apkParser.js
import fs from "fs";
import path from "path";
import ApkReader from "node-apk-parser";

export async function parseApkFromBuffer(buffer) {
  return new Promise((resolve, reject) => {
    try {
      // 1️⃣ Create /tmp folder if not exists
      const tempDir = path.join(process.cwd(), "tmp");
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir);
      }

      // 2️⃣ Save buffer to temp file
      const tempFilePath = path.join(tempDir, `upload_${Date.now()}.apk`);
      fs.writeFileSync(tempFilePath, buffer);

      // 3️⃣ Parse APK
      const reader = ApkReader.readFile(tempFilePath);
      const manifest = reader.readManifestSync();

      // 4️⃣ Cleanup file
      fs.unlinkSync(tempFilePath);

      resolve(manifest);
    } catch (err) {
      reject(err);
    }
  });
}
