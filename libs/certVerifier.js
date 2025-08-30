// src/libs/certVerifier.js
import unzipper from "unzipper";
import forge from "node-forge";
import TrustedCert from "@/models/TrustedCert";

/**
 * Extract first signing certificate from META-INF/*.RSA|*.DSA|*.EC
 * and run basic verification heuristics.
 *
 * @param {Buffer} apkBuffer
 * @returns {Promise<{found:boolean, certificate?:object, warnings?:string[]}>}
 */
export async function verifyApkCertificate(apkBuffer) {
  // 1) Find a signature block in the APK zip
  const sigEntry = await findSignatureEntry(apkBuffer);
  if (!sigEntry) {
    return {
      found: false,
      warnings: ["No signature file found in META-INF (v1). This APK may rely on v2/v3 signing or be unsigned."],
    };
  }

  // 2) Parse PKCS#7 and extract X.509 cert
  let cert;
  try {
    const asn1 = forge.asn1.fromDer(sigEntry.toString("binary"));
    const p7 = forge.pkcs7.messageFromAsn1(asn1);
    if (!p7.certificates || p7.certificates.length === 0) {
      return {
        found: false,
        warnings: ["Signature block present, but no certificate embedded."],
      };
    }
    cert = p7.certificates[0]; // use leaf (first) certificate
  } catch (e) {
    return {
      found: false,
      warnings: ["Failed to parse certificate from signature block: " + e.message],
    };
  }

  // 3) Build a readable cert object
  const subject = dnToObject(cert.subject);
  const issuer = dnToObject(cert.issuer);
  const notBefore = cert.validity.notBefore;
  const notAfter = cert.validity.notAfter;

  // Compute SHA-256 fingerprint from DER
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const sha256 = forge.md.sha256.create().update(derBytes).digest().toHex();

  // Public key info
  let keySizeBits = null;
  let keyType = null;
  try {
    if (cert.publicKey && cert.publicKey.n) {
      keyType = "RSA";
      keySizeBits = cert.publicKey.n.bitLength();
    } else if (cert.publicKey && cert.publicKey.ecparams) {
      keyType = "EC";
      keySizeBits = cert.publicKey.ecparams.size;
    }
  } catch {
    // ignore
  }

  // Signature algorithm (OID → string best effort)
  const sigOid = cert.signatureOid || cert.siginfo?.algorithmOid;
  const sigAlg = oidToName(sigOid);

  // 4) Heuristics / warnings
  const now = new Date();
  const warnings = [];

  // Expiration
  if (notAfter && now > notAfter) warnings.push("Certificate expired.");
  if (notBefore && now < notBefore) warnings.push("Certificate not yet valid.");

  // Self-signed (subject == issuer)
  const isSelfSigned = sameDN(cert.subject, cert.issuer);
  if (isSelfSigned) warnings.push("Self-signed certificate.");

  // Debug keystore (very common for malware/test builds)
  const subjectCN = subject.CN || "";
  const issuerCN = issuer.CN || "";
  const debugIndicators = ["Android Debug", "Android Debug Keystore"];
  if (debugIndicators.some(s => subjectCN.includes(s) || issuerCN.includes(s))) {
    warnings.push("Signed with Android Debug keystore.");
  }

  // Weak signature algorithms
  if (/md5/i.test(sigAlg)) warnings.push("Weak signature algorithm (MD5).");
  if (/sha1/i.test(sigAlg)) warnings.push("Outdated signature algorithm (SHA-1).");

  // Weak key sizes
  if (keyType === "RSA" && keySizeBits && keySizeBits < 2048) {
    warnings.push(`Weak RSA key size (${keySizeBits} bits).`);
  }

  // Build result
  const certificate = {
    subject,
    issuer,
    subjectCN,
    issuerCN,
    validFrom: notBefore?.toISOString?.() || null,
    validTo: notAfter?.toISOString?.() || null,
    sha256Fingerprint: sha256,
    keyType,
    keySizeBits,
    signatureAlgorithm: sigAlg,
    isSelfSigned,
  };


 

const trusted = await TrustedCert.findOne({ sha256Fingerprint: sha256 });
let trustStatus = "unknown";
if (trusted) trustStatus = "trusted";
else if (isSelfSigned) trustStatus = "self-signed";
else if (warnings.includes("Certificate expired.")) trustStatus = "expired";


  return { found: true, certificate, warnings };
}

/** Helpers **/

async function findSignatureEntry(apkBuffer) {
  // Scan zip entries in-memory with unzipper
  const dir = await unzipper.Open.buffer(apkBuffer);
  // Prefer *.RSA, then *.DSA, then *.EC
  const candidate = dir.files.find(f => /^META-INF\/.+\.(RSA)$/i.test(f.path))
    || dir.files.find(f => /^META-INF\/.+\.(DSA)$/i.test(f.path))
    || dir.files.find(f => /^META-INF\/.+\.(EC)$/i.test(f.path));

  if (!candidate) return null;
  const content = await candidate.buffer();
  return content;
}

function dnToObject(name) {
  const obj = {};
  (name?.attributes || []).forEach(attr => {
    obj[attr.shortName || attr.name] = attr.value;
  });
  return obj;
}

function sameDN(a, b) {
  const aStr = (a?.attributes || []).map(x => `${x.shortName || x.name}=${x.value}`).join(",");
  const bStr = (b?.attributes || []).map(x => `${x.shortName || x.name}=${x.value}`).join(",");
  return aStr === bStr;
}

function oidToName(oid) {
  if (!oid) return "unknown";
  const map = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  };
  return map[oid] || oid;
}
