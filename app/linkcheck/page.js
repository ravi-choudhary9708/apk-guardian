"use client";
import { useState } from "react";

export default function LinkChecker() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  async function handleCheck() {
    const res = await fetch("/api/link-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url }),
    });
    const data = await res.json();
    setResult(data);
  }

  return (
    <div className="p-4 max-w-lg mx-auto">
      <h1 className="text-xl font-bold mb-3">APK Link Checker</h1>
      <input
        type="text"
        placeholder="Paste APK link..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        className="border p-2 w-full mb-2"
      />
      <button onClick={handleCheck} className="bg-blue-600 text-white px-4 py-2 rounded">
        Check Link
      </button>

      {result && (
        <div className="mt-4 border p-3 rounded">
          {result.success ? (
            <div>
              <h2 className="font-bold">{result.appInfo.title}</h2>
              <p>Developer: {result.appInfo.developer}</p>
              <p>Version: {result.appInfo.version}</p>
              <p>Installs: {result.appInfo.installs}</p>
              <p>Score: {result.appInfo.score}</p>
              <a href={result.appInfo.link} target="_blank" className="text-blue-500 underline">
                Official Play Store Link
              </a>
            </div>
          ) : (
            <div>
              <p className="text-red-600">{result.message}</p>
              {result.officialLink && (
                <a href={result.officialLink} target="_blank" className="text-blue-500 underline">
                  Find Official App Here
                </a>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
