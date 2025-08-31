// models/TrustedCert.js
import mongoose from "mongoose";

const TrustedCertSchema = new mongoose.Schema({
  bankName: {
    type: String,
    required: true, // e.g., "State Bank of India"
  },
  packageNames: [
    {
      type: String,
    },
  ], // optional: link cert to known package names
  certFingerprint: {
    type: String,
    required: true, // SHA-256 fingerprint
    unique: true,
  },
  issuer: {
    type: String,
  }, // Certificate Issuer details
  subject: {
    type: String,
  }, // Certificate Subject (developer/org name)
  validFrom: {
    type: Date,
  },
  validTo: {
    type: Date,
  },
  notes: {
    type: String,
  }, // optional: any manual notes
  addedBy: {
    type: String,
  }, // which admin added this cert
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.models.TrustedCert ||
  mongoose.model("TrustedCert", TrustedCertSchema);

