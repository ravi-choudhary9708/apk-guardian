import { NextResponse } from "next/server";

import Report from "@/models/Report";
import dbConnect from "@/libs/db";
import { detectFake } from "@/libs/detector";
import { scanAndSummarizeWithVirusTotal } from "@/libs/virusTotal";
import crypto from "crypto";
import { verifyApkCertificate } from "@/libs/certVerifier";
import Certificate from "@/models/Certificate";
import TrustedCert from "@/models/TrustedCert";
import { analyzeNetwork } from "@/libs/networkAnalyzer";
import { calculateRiskScore } from "@/libs/riskCalculator";
import { v2 as cloudinary } from "cloudinary";

// Cloudinary setup
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Banking app baseline permissions
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

    // Validate file type
    if (!file.name.endsWith(".apk")) {
      return NextResponse.json({ success: false, error: "Only .apk files are allowed" }, { status: 400 });
    }

    // Validate file size (<10MB)
    const MAX_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      return NextResponse.json({ success: false, error: "File too large. Max 10MB allowed." }, { status: 400 });
    }

    // Convert file to Buffer
    const buffer = Buffer.from(await file.arrayBuffer());

    // Upload to Cloudinary
    const uploadedFile = await new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        { resource_type: "raw", folder: "apk_uploads" }, // keep as raw to support .apk
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      ).end(buffer);
    });

    const fileUrl = uploadedFile.secure_url;
    const fileName = uploadedFile.original_filename;

    // Generate SHA256 hash
    const hash = crypto.createHash("sha256").update(buffer).digest("hex");

    // SOLUTION 1: Try different import approaches for apk-parser3
    let manifest, permissions = [], apkMeta = {};
    
    try {
      // Method 1: Try default import
      const apkParser = await import("apk-parser3");
      
      if (apkParser.default && apkParser.default.readBuffer) {
        const reader = apkParser.default.readBuffer(buffer);
        manifest = reader.readManifestSync();
      } else if (apkParser.ApkReader) {
        // Method 2: Named import
        const reader = apkParser.ApkReader.readBuffer(buffer);
        manifest = reader.readManifestSync();
      } else if (apkParser.readBuffer) {
        // Method 3: Direct function import
        const reader = apkParser.readBuffer(buffer);
        manifest = reader.readManifestSync();
      } else {
        throw new Error("ApkReader.readBuffer not found in any expected location");
      }

      // Extract permissions
      permissions = manifest.usesPermissions?.map(p => p.name) || [];

      apkMeta = {
        packageName: manifest.package,
        versionName: manifest.versionName,
        versionCode: manifest.versionCode?.toString(),
        permissions: permissions,
      };

    } catch (parseError) {
      console.error("APK parsing failed:", parseError);
      
      // Fallback: Create basic metadata without parsing
      apkMeta = {
        packageName: "unknown",
        versionName: "unknown", 
        versionCode: "unknown",
        permissions: [],
      };
      
      permissions = [];
    }

    // Analyze permissions
    const flaggedSuspicious = permissions.filter(p => suspiciousPermissions.includes(p));
    const missingBaseline = bankingBaseline.filter(base => !permissions.includes(base));

    const permissionAnalysis = {
      totalPermissions: permissions.length,
      allPermissions: permissions,
      flaggedSuspicious,
      missingBaseline
    };

    // Run fake detector
    const { isFake, reasons } = detectFake(apkMeta);

    // VirusTotal Scan
    const vtresult = await scanAndSummarizeWithVirusTotal(buffer, file.name);

    // Certificate verification
    const certCheck = await verifyApkCertificate(buffer);

    // Network analysis
    const networkCheck = await analyzeNetwork(buffer);

    const riskLevel = calculateRiskScore({
      certificate: certCheck.certificate,
      virusTotal: vtresult,
      permissions: permissionAnalysis,
      networkAnalysis: networkCheck,
    });

    // 🔍 TrustedCert DB Lookup
    let trustStatus = "unknown";
    let bankMatch = null;

    if (certCheck?.certificate?.sha256Fingerprint) {
      const trusted = await TrustedCert.findOne({
        certFingerprint: certCheck.certificate.sha256Fingerprint,
      });

      if (trusted) {
        trustStatus = "trusted";
        bankMatch = trusted.bankName;
      } else if (certCheck.certificate.isSelfSigned) {
        trustStatus = "self-signed";
      } else {
        trustStatus = "untrusted";
      }

      if (certCheck.certificate.validTo && new Date(certCheck.certificate.validTo) < new Date()) {
        trustStatus = "expired";
      }
    }

    // Save metadata to MongoDB
    const report = await Report.create({
      hash,
      size: buffer.length,
      uploaderIp,
      userAgent,
      fileName,
      fileUrl,
      publicId: uploadedFile.public_id,
      packageName: apkMeta.packageName,
      versionName: apkMeta.versionName,
      versionCode: apkMeta.versionCode,
      permissions: apkMeta.permissions,
      detectionResult: isFake ? "fake" : "safe",
      reasons,
      trustStatus,
      bankMatch,
    });

    const certificate = await Certificate.create({
      sha256Fingerprint: certCheck.certificate?.sha256Fingerprint,
      subjectCN: certCheck.certificate?.subjectCN,
      issuerCN: certCheck.certificate?.issuerCN,
      validFrom: certCheck.certificate?.validFrom,
      validTo: certCheck.certificate?.validTo,
      signatureAlgorithm: certCheck.certificate?.signatureAlgorithm,
      keyType: certCheck.certificate?.keyType,
      keySizeBits: certCheck.certificate?.keySizeBits,
      isSelfSigned: certCheck.certificate?.isSelfSigned,
      warnings: certCheck.warnings || [],
      detectionResult: isFake ? "fake" : "safe",
      trustStatus,
      bankMatch,
    });

    return NextResponse.json({
      success: true,
      apkMeta,
      analysis: {
        fakeCheck: isFake,
        virusTotal: vtresult,
        networkAnalysis: networkCheck,
        riskLevel: riskLevel,
      },
      permissions: permissionAnalysis,
      result: { isFake, reasons },
      certificate,
      trust: { trustStatus, bankMatch },
      reportId: report._id,
      cloudinaryUrl: fileUrl,
    });
  } catch (err) {
    console.error("Upload error:", err);
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}