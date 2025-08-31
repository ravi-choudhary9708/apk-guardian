"use client";

import { useState } from "react";

export default function Home() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleUpload(e) {
    e.preventDefault();
    if (!file) {
      setError("Please select an APK file.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Upload failed");

      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError("Something went wrong!");
    } finally {
      setLoading(false);
    }
  }

  function renderFakeCheck(fakeCheck, reasons) {
    if (fakeCheck) {
      return (
        <p style={{ color: "red", fontWeight: "bold" }}>
          ❌ Fake / Unsafe
          {reasons?.length > 0 && (
            <ul>
              {reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}
        </p>
      );
    }
    return <p style={{ color: "green", fontWeight: "bold" }}>✅ No Fake Indicators</p>;
  }

  function renderVirusTotal(vt) {
    if (!vt || !vt?.data?.attributes?.stats) {
      return <p>⚠ VirusTotal report not available</p>;
    }

    const stats = vt.data.attributes.stats;
    let verdict = "✅ Clean";
    let color = "green";

    if (stats.malicious > 0) {
      verdict = "❌ Malicious";
      color = "red";
    } else if (stats.suspicious > 0) {
      verdict = "⚠ Suspicious";
      color = "orange";
    }

    return (
      <div>
        <p style={{ color, fontWeight: "bold" }}>{verdict}</p>
        <p>
          Malicious: {stats.malicious} | Suspicious: {stats.suspicious} | Undetected:{" "}
          {stats.undetected}
        </p>
        <a
          href={vt.data.links?.self}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: "inline-block",
            marginTop: "8px",
            padding: "6px 12px",
            background: "#2563eb",
            color: "white",
            borderRadius: "6px",
            textDecoration: "none",
          }}
        >
          🔗 View Full Report
        </a>
      </div>
    );
  }

  function renderCertificate(cert, trust) {
    if (!cert) return null;

    return (
      <div style={{ marginTop: "15px" }}>
        <h2>🔑 Certificate</h2>
        <p><strong>Fingerprint:</strong> {cert.sha256Fingerprint}</p>
        <p><strong>Subject:</strong> {cert.subjectCN}</p>
        <p><strong>Issuer:</strong> {cert.issuerCN}</p>
        <p><strong>Valid From:</strong> {new Date(cert.validFrom).toLocaleString()}</p>
        <p><strong>Valid To:</strong> {new Date(cert.validTo).toLocaleString()}</p>
        <p><strong>Algorithm:</strong> {cert.signatureAlgorithm}</p>
        <p><strong>Key:</strong> {cert.keyType} ({cert.keySizeBits} bits)</p>
        <p><strong>Self-signed:</strong> {cert.isSelfSigned ? "Yes" : "No"}</p>
        {cert.warnings?.length > 0 && (
          <ul style={{ color: "orange" }}>
            {cert.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        )}
        <h3>Trust Check</h3>
        <p>
          <strong>Status:</strong>{" "}
          {trust?.trustStatus === "trusted" ? (
            <span style={{ color: "green" }}>✅ Trusted</span>
          ) : trust?.trustStatus === "self-signed" ? (
            <span style={{ color: "orange" }}>⚠ Self-signed</span>
          ) : (
            <span style={{ color: "red" }}>❌ Unknown</span>
          )}
        </p>
        {trust?.bankMatch && <p><strong>Bank Match:</strong> {trust.bankMatch}</p>}
      </div>
    );
  }

  function renderPermissions(perms) {
    if (!perms) return null;

    return (
      <div>
        <h2>🔒 Permissions Analysis</h2>
        <p><strong>Total Permissions:</strong> {perms.totalPermissions}</p>
        <p><strong>Suspicious:</strong></p>
        {perms.flaggedSuspicious.length > 0 ? (
          <ul>
            {perms.flaggedSuspicious.map((p, i) => (
              <li key={i} style={{ color: "red" }}>{p}</li>
            ))}
          </ul>
        ) : (
          <p>No suspicious permissions.</p>
        )}
        <p><strong>Missing Baseline:</strong></p>
        {perms.missingBaseline.length > 0 ? (
          <ul>
            {perms.missingBaseline.map((p, i) => (
              <li key={i} style={{ color: "orange" }}>{p}</li>
            ))}
          </ul>
        ) : (
          <p>All baseline permissions present.</p>
        )}
      </div>
    );
  }

  return (
    <div style={{ maxWidth: "700px", margin: "50px auto", textAlign: "center" }}>
      <h1>APK Guardian</h1>
      <p>Upload an APK file for metadata, permission, certificate & VirusTotal checks</p>

      <form onSubmit={handleUpload}>
        <input
          type="file"
          accept=".apk"
          onChange={(e) => setFile(e.target.files[0])}
        />
        <br />
        <button
          type="submit"
          disabled={loading}
          style={{
            marginTop: "10px",
            padding: "8px 16px",
            cursor: "pointer",
            backgroundColor: "#2563eb",
            color: "white",
            border: "none",
            borderRadius: "6px",
          }}
        >
          {loading ? "Uploading & Analyzing..." : "Upload & Analyze"}
        </button>
      </form>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {result && (
        <div
          style={{
            marginTop: "20px",
            padding: "15px",
            border: "1px solid #ccc",
            borderRadius: "8px",
            textAlign: "left",
            background: "#f9fafb",
          }}
        >
          <h2>📦 APK Metadata</h2>
          <p><strong>File:</strong> {file?.name}</p>
          <p><strong>Package:</strong> {result.apkMeta?.packageName}</p>
          <p>
            <strong>Version:</strong> {result.apkMeta?.versionName} ({result.apkMeta?.versionCode})
          </p>
          <p><strong>Permissions:</strong></p>
          <ul>
            {result.apkMeta?.permissions?.length > 0 ? (
              result.apkMeta.permissions.map((perm, i) => <li key={i}>{perm}</li>)
            ) : (
              <li>No special permissions</li>
            )}
          </ul>

          <h2>🧪 Analysis</h2>
          {renderFakeCheck(result.result?.isFake, result.result?.reasons)}
          {renderVirusTotal(result.analysis?.virusTotal)}
          {renderPermissions(result.permissions)}
          {renderCertificate(result.certificate, result.trust)}
        </div>
      )}
    </div>
  );
}
