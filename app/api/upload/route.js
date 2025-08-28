import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import ApkReader from "node-apk-parser";
import Report from "@/models/Report";
import dbConnect from "@/libs/db";
import { detectFake } from "@/libs/detector";
import { scanWithVirusTotal, getVirusTotalReport } from "@/libs/virusTotal";
import crypto from "crypto";

// Banking app baseline permissions (example set)
const bankingBaseline = [
  "android.permission.INTERNET",
  "android.permission.ACCESS_NETWORK_STATE",
  "android.permission.RECEIVE_SMS",
  "android.permission.READ_PHONE_STATE"
];

// Suspicious / dangerous permissions
const suspiciousPermissions = [
  "android.permission.READ_SMS",
  "android.permission.SEND_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAMERA",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.READ_CONTACTS",
  "android.permission.ACCESS_FINE_LOCATION"
];


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
      return NextResponse.json({ success: false, error: "No file uploaded" }, { status: 400 });
    }

    // Trace log info
    const headers = req.headers;
    const uploaderIp = headers.get("x-forwarded-for") || "unknown";
    const userAgent = headers.get("user-agent");

    // ✅ Validate file type
    if (!file.name.endsWith(".apk")) {
      return NextResponse.json({ success: false, error: "Only .apk files are allowed" }, { status: 400 });
    }

    // ✅ Validate file size (<10MB)
    const MAX_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      return NextResponse.json({ success: false, error: "File too large. Max 10MB allowed." }, { status: 400 });
    }

    // Save file
    const buffer = Buffer.from(await file.arrayBuffer());
    const fileName = `${Date.now()}-${file.name}`;
    const filePath = path.join(uploadDir, fileName);
    fs.writeFileSync(filePath, buffer);

    // ✅ Generate SHA256 hash
    const hash = crypto.createHash("sha256").update(buffer).digest("hex");

    // ✅ Parse APK metadata
    const reader = ApkReader.readFile(filePath);
    const manifest = reader.readManifestSync();

      // Extract permissions
    const permissions = manifest.usesPermissions?.map(p => p.name) || [];

    // Analyze permissions
    const flaggedSuspicious = permissions.filter(p =>
      suspiciousPermissions.includes(p)
    );
    const missingBaseline = bankingBaseline.filter(
      base => !permissions.includes(base)
    );

    const permissionAnalysis = {
      totalPermissions: permissions.length,
      allPermissions: permissions,
      flaggedSuspicious,
      missingBaseline
    };

    const apkMeta = {
      packageName: manifest.package,
      versionName: manifest.versionName,
      versionCode: manifest.versionCode?.toString(),
      permissions: manifest.usesPermissions ? manifest.usesPermissions.map((p) => p.name) : [],
    };

    // ✅ Run fake detector
    const { isFake, reasons } = detectFake(apkMeta);

// 2. VirusTotal Scan
    const vtScan = await scanWithVirusTotal(buffer, file.name);
    let vtReport = null;
    if (vtScan?.data?.id) {
      vtReport = await getVirusTotalReport(vtScan.data.id);
    }
    console.log("vtscan:",vtScan);
    console.log("vtreport",vtReport);

    // ✅ Save metadata to MongoDB
    const report = await Report.create({
      hash,
      size: buffer.length,
      uploaderIp,
      userAgent,
      fileName,
      fileUrl: filePath,
      publicId: fileName,
      packageName: apkMeta.packageName,
      versionName: apkMeta.versionName,
      versionCode: apkMeta.versionCode,
      permissions: apkMeta.permissions,
      detectionResult: isFake ? "fake" : "safe",
      reasons,
    });

    return NextResponse.json({
      success: true,
      apkMeta,
       analysis: {
          fakeCheck:isFake,
          virusTotal: vtReport,
        },
        permissions: permissionAnalysis,
      result: { isFake, reasons },
      reportId: report._id,
    });
  } catch (err) {
    console.error("Upload error:", err);
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
