import mongoose from "mongoose";

const ScanResultSchema = new mongoose.Schema({
 
  fileHash: String,
  permissions: [String],
  developer: String,
  status: { type: String, enum: ["safe", "suspicious", "malicious"] },
  explanation: String,
  uploadedAt: { type: Date, default: Date.now },
});

export default mongoose.models.ScanResult || mongoose.model("ScanResult", ScanResultSchema);
