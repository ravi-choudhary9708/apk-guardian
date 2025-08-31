'use client';

import { useState } from 'react';
import {
  Upload,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  FileText,
  Wifi,
  Key,
  Users,
  Loader2,
} from 'lucide-react';

export default function APKGuardian() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  const handleFileUpload = async (file) => {
    if (!file || !file.name.endsWith('.apk')) {
      setError('Please upload a valid .apk file');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('File size must be less than 10MB');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.error || 'Upload failed');
      setResult(data);
    } catch (err) {
      setError(err.message || 'Something went wrong!');
    } finally {
      setLoading(false);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const riskScore = result?.analysis?.riskLevel?.score || 0;
  const riskReasons = result?.analysis?.riskLevel?.reasons || [];

  const getRiskColor = (score) => {
    if (score >= 70) return 'text-red-600 bg-red-50 border-red-200';
    if (score >= 40) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
    return 'text-green-600 bg-green-50 border-green-200';
  };

  const getRiskLevel = (score) => {
    if (score >= 70) return 'HIGH RISK';
    if (score >= 40) return 'MEDIUM RISK';
    return 'LOW RISK';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-slate-900">
      {/* Header */}
      <div className="bg-white/10 backdrop-blur-md border-b border-white/20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center space-x-3">
          <Shield className="h-8 w-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">APK Guardian</h1>
            <p className="text-blue-200 text-sm">
              Upload an APK for metadata, certificate & VirusTotal analysis
            </p>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {!result ? (
          /* Upload Section */
          <div className="grid lg:grid-cols-2 gap-8">
            <div
              className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 p-8"
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
            >
              <h2 className="text-xl font-semibold text-white mb-6 flex items-center">
                <Upload className="mr-3 h-6 w-6 text-cyan-400" /> Upload APK
              </h2>
              <div
                className={`border-2 border-dashed rounded-xl p-12 text-center transition-all duration-300 ${
                  dragActive
                    ? 'border-cyan-400 bg-cyan-400/10'
                    : 'border-white/30 hover:border-cyan-400/50'
                }`}
              >
                <div className="space-y-4">
                  <div className="mx-auto w-16 h-16 bg-cyan-400/20 rounded-full flex items-center justify-center">
                    <Upload className="h-8 w-8 text-cyan-400" />
                  </div>
                  <p className="text-white font-medium">Drop your APK file here</p>
                  <p className="text-blue-200 text-sm">(Max 10MB)</p>
                  <button
                    onClick={() => document.getElementById('file-input')?.click()}
                    className="bg-cyan-500 hover:bg-cyan-400 text-white px-6 py-2 rounded-lg font-medium transition-colors disabled:opacity-50"
                    disabled={loading}
                  >
                    {loading ? 'Analyzing...' : 'Choose File'}
                  </button>
                  <input
                    id="file-input"
                    type="file"
                    accept=".apk"
                    className="hidden"
                    onChange={(e) =>
                      e.target.files?.[0] && handleFileUpload(e.target.files[0])
                    }
                    disabled={loading}
                  />
                </div>
              </div>
              {error && (
                <div className="mt-4 bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-red-200 text-sm">
                  <AlertTriangle className="inline h-5 w-5 mr-2 text-red-400" />
                  {error}
                </div>
              )}
            </div>

            {/* Features Card */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 p-8">
              <h2 className="text-xl font-semibold text-white mb-6">Features</h2>
              <ul className="space-y-3 text-blue-200 text-sm">
                <li>🔒 Certificate & trust validation</li>
                <li>🦠 VirusTotal multi-engine scan</li>
                <li>📡 Network behavior analysis</li>
                <li>📋 Permission profiling</li>
              </ul>
            </div>
          </div>
        ) : (
          /* Results */
          <div className="space-y-6">
            <div className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 p-8">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-white">Analysis Result</h2>
                <button
                  onClick={() => setResult(null)}
                  className="text-blue-200 hover:text-white"
                >
                  Analyze Another
                </button>
              </div>

              {/* Summary */}
              <div className="grid md:grid-cols-3 gap-6">
                <div className="text-center">
                  <FileText className="h-8 w-8 text-blue-400 mx-auto mb-2" />
                  <h3 className="text-white font-medium">
                    {result.apkMeta?.packageName}
                  </h3>
                  <p className="text-blue-200 text-sm">
                    v{result.apkMeta?.versionName} ({result.apkMeta?.versionCode})
                  </p>
                </div>
                <div className="text-center">
                  <div
                    className={`mx-auto w-16 h-16 rounded-full flex items-center justify-center mb-3 border-2 ${getRiskColor(
                      riskScore
                    )}`}
                  >
                    {riskScore >= 70 ? (
                      <XCircle className="h-8 w-8" />
                    ) : riskScore >= 40 ? (
                      <AlertTriangle className="h-8 w-8" />
                    ) : (
                      <CheckCircle className="h-8 w-8" />
                    )}
                  </div>
                  <h3 className="text-white font-medium">{getRiskLevel(riskScore)}</h3>
                  <p className="text-blue-200 text-sm">Score: {riskScore}/100</p>
                </div>
                <div className="text-center">
                  <Shield className="h-8 w-8 text-green-400 mx-auto mb-2" />
                  <h3 className="text-white font-medium">
                    {(result.analysis?.virusTotal?.stats?.malicious || 0) +
                      (result.analysis?.virusTotal?.stats?.suspicious || 0)}
                  </h3>
                  <p className="text-blue-200 text-sm">Threats Detected</p>
                </div>
              </div>

              {riskReasons.length > 0 && (
                <div className="mt-6 bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-200 text-sm">
                  <AlertTriangle className="inline h-5 w-5 mr-2 text-red-400" />
                  {riskReasons.map((r, i) => (
                    <div key={i}>• {r}</div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {loading && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center">
            <div className="bg-white/10 border border-white/20 rounded-2xl p-8 text-center">
              <Loader2 className="h-12 w-12 text-cyan-400 animate-spin mx-auto mb-3" />
              <p className="text-white">Analyzing APK...</p>
              <p className="text-blue-200 text-sm">
                This may take up to 30 seconds
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
