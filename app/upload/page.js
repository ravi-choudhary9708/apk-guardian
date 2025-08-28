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

      if (!res.ok) {
        throw new Error("Upload failed");
      }

      const data = await res.json();
      setResult(data.report); // ✅ take report object directly
    } catch (err) {
      console.error(err);
      setError("Something went wrong!");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: "600px", margin: "50px auto", textAlign: "center" }}>
      <h1>APK Guardian</h1>
      <p>Upload an APK file to analyze its metadata</p>

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
          }}
        >
          {loading ? "Uploading..." : "Upload & Analyze"}
        </button>
      </form>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {result && (
        <div
          style={{
            marginTop: "20px",
            padding: "15px",
            border: "1px solid #ccc",
            borderRadius: "5px",
            textAlign: "left",
          }}
        >
          <h2>Analysis Result</h2>
          <p><strong>File Name:</strong> {result.fileName}</p>
          <p><strong>Package:</strong> {result.packageName}</p>
          <p><strong>Version:</strong> {result.versionName} ({result.versionCode})</p>
          <p>
            <strong>Status:</strong>{" "}
            {result.detectionResult === "safe" ? "✅ Safe" :
             result.detectionResult === "fake" ? "❌ Fake" : "⚠ Suspicious"}
          </p>

          {result.reasons && result.reasons.length > 0 && (
            <>
              <p><strong>Reasons:</strong></p>
              <ul>
                {result.reasons.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            </>
          )}

          <p><strong>Permissions:</strong></p>
          <ul>
            {result.permissions && result.permissions.length > 0 ? (
              result.permissions.map((perm, i) => <li key={i}>{perm}</li>)
            ) : (
              <li>No special permissions</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}
