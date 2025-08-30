import mongoose from "mongoose";

const CertificateSchema = new mongoose.Schema({

  sha256Fingerprint: String,
  subjectCN: String,
  issuerCN: String,
  validFrom: Date,
  validTo: Date,
  signatureAlgorithm: String,
  keyType: String,
  keySizeBits: Number,
  isSelfSigned: Boolean,
  warnings: [String],
})


export default mongoose.models.Certificate || mongoose.model("Certificate", CertificateSchema);
