// src/lib/models/Report.js
import mongoose from "mongoose";

const ReportSchema = new mongoose.Schema(
  {
    fileName: { type: String, required: true },
    hash: { type: String, required: true },
    uploaderIp: { type: String, required: true },
    userAgent: { type: String, required: true },
    fileUrl: { type: String, required: true }, // Cloudinary URL
    publicId: { type: String, required: true }, // Cloudinary public_id for deletion

    packageName: { type: String },
    size: { type: Number },
    versionName: { type: String },
    versionCode: { type: String },
    permissions: [{ type: String }],

    detectionResult: { type: String, enum: ["safe", "fake", "suspicious"], default: "suspicious" },
    reasons: [{ type: String }], // why it was marked fake/safe

    uploadedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export default mongoose.models.Report || mongoose.model("Report", ReportSchema);
