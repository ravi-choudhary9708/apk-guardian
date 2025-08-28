"use client";

import { useState } from "react";

export default function Home() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [apkMeta, setApkMeta] = useState(null);
  const [error, setError] = useState(null);

  async function handleUpload(e) {
    e.preventDefault();
    if (!file) {
      setError("Please select an APK file.");
      return;
    }

    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Upload failed");

      const data = await res.json();
      setApkMeta(data.apkMeta);
      setAnalysis(data.analysis);
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
    if (!vt?.data?.attributes?.stats) {
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

  return (
    <div style={{ maxWidth: "600px", margin: "50px auto", textAlign: "center" }}>
      <h1>APK Guardian</h1>
      <p>Upload an APK file for fake detection & VirusTotal scan</p>

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

      {(apkMeta || analysis) && (
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
          <p><strong>Package:</strong> {apkMeta?.packageName}</p>
          <p>
            <strong>Version:</strong> {apkMeta?.versionName} ({apkMeta?.versionCode})
          </p>
          <p><strong>Permissions:</strong></p>
          <ul>
            {apkMeta?.permissions?.length > 0 ? (
              apkMeta.permissions.map((perm, i) => <li key={i}>{perm}</li>)
            ) : (
              <li>No special permissions</li>
            )}
          </ul>

          <h2>🧪 Analysis</h2>
          {renderFakeCheck(analysis?.fakeCheck, analysis?.reasons)}
          {renderVirusTotal(analysis?.virusTotal)}
        </div>
      )}
    </div>
  );
}
