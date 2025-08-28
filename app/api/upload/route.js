import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import ApkReader from "node-apk-parser"; // ✅ correct import
import Report from "@/models/Report";
import dbConnect from "@/libs/db";
import { detectFake } from "@/libs/detector";

// Ensure /uploads exists
const uploadDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

export async function POST(req) {
  try {
    await dbConnect();

    // Get form-data
    const formData = await req.formData();
    const file = formData.get("file");

    if (!file) {
      return NextResponse.json({ error: "No file uploaded" }, { status: 400 });
    }

    const buffer = Buffer.from(await file.arrayBuffer());
    const fileName = `${Date.now()}-${file.name}`;
    const filePath = path.join(uploadDir, fileName);

    // Save file locally
    fs.writeFileSync(filePath, buffer);

    // ✅ Parse APK metadata
    const reader = ApkReader.readFile(filePath); 
    const manifest = reader.readManifestSync();
    console.log("manifest:",manifest);


    const apkMeta = {
      packageName: manifest.package,
      versionName: manifest.versionName,
      versionCode: manifest.versionCode?.toString(),
      permissions: manifest.usesPermissions
        ? manifest.usesPermissions.map((p) => p.name)
        : [],
    };

    // Run fake detector
    const { isFake, reasons } = detectFake(apkMeta);
    console.log("isfake:",isFake);
    console.log("reason:",reasons);

    // Save metadata to MongoDB
    const report = await Report.create({
      fileName,
      fileUrl: filePath, // local storage path
      publicId: fileName, // temp placeholder
      packageName: apkMeta.packageName,
      versionName: apkMeta.versionName,
      versionCode: apkMeta.versionCode,
      permissions: apkMeta.permissions,
      detectionResult: isFake ? "fake" : "safe",
      reasons,
    });

    return NextResponse.json({ success: true, report });
  } catch (err) {
    console.error("Upload error:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
