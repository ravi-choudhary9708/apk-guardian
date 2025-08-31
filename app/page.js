'use client';

import { useState } from 'react';
import {
  Upload,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  FileText,
  Key,
  Users,
  Loader2,
  ExternalLink,
  Search,
} from 'lucide-react';

// This is a single-file React component that combines APK file analysis and link checking.
// It now relies on the actual API endpoints for data.
export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [viewMode, setViewMode] = useState('upload'); // 'upload' or 'link'
  const [url, setUrl] = useState('');

  // Handles file upload and makes the API call to the backend.
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
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Upload failed');
      }
      setResult(data);
    } catch (err) {
      setError(err.message || 'Something went wrong!');
    } finally {
      setLoading(false);
    }
  };

  // Handles link checking and makes the API call to the backend.
  const handleLinkCheck = async () => {
    if (!url) {
      setError('Please enter a URL to check.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/api/link-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Link check failed');
      }
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
  
  const totalThreats = (result?.analysis?.virusTotal?.stats?.malicious || 0) + (result?.analysis?.virusTotal?.stats?.suspicious || 0);

  return (
    <div className="min-h-screen font-[Inter] bg-gradient-to-br from-blue-950 via-blue-900 to-slate-950 text-white">
      {/* Header */}
      <div className="bg-white/5 backdrop-blur-md border-b border-white/10 shadow-lg">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center space-x-3">
          <Shield className="h-8 w-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">APK Guardian</h1>
            <p className="text-blue-200 text-sm">
              Securely analyze APK files & links
            </p>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-12">
        {!result ? (
          /* Main Analysis Section */
          <div className="bg-white/5 backdrop-blur-lg rounded-3xl border border-white/10 p-8 shadow-2xl">
            {/* Mode Switcher */}
            <div className="flex justify-center mb-8">
              <div className="bg-white/10 p-1 rounded-full">
                <button
                  onClick={() => setViewMode('upload')}
                  className={`px-6 py-2 rounded-full font-medium transition-all duration-300 ${
                    viewMode === 'upload'
                      ? 'bg-cyan-500 text-white shadow-lg'
                      : 'text-blue-200 hover:bg-white/10'
                  }`}
                >
                  <Upload className="inline-block h-4 w-4 mr-2" /> Upload APK
                </button>
                <button
                  onClick={() => setViewMode('link')}
                  className={`px-6 py-2 rounded-full font-medium transition-all duration-300 ${
                    viewMode === 'link'
                      ? 'bg-cyan-500 text-white shadow-lg'
                      : 'text-blue-200 hover:bg-white/10'
                  }`}
                >
                  <Search className="inline-block h-4 w-4 mr-2" /> Check Link
                </button>
              </div>
            </div>

            {/* Content based on view mode */}
            {viewMode === 'upload' ? (
              <div
                className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 ${
                  dragActive
                    ? 'border-cyan-400 bg-cyan-400/10'
                    : 'border-white/20 hover:border-cyan-400/50'
                }`}
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
              >
                <div className="space-y-4">
                  <div className="mx-auto w-16 h-16 bg-cyan-400/20 rounded-full flex items-center justify-center">
                    <Upload className="h-8 w-8 text-cyan-400" />
                  </div>
                  <p className="text-white font-semibold text-lg">Drop your APK file here</p>
                  <p className="text-blue-200 text-sm">(Max 10MB)</p>
                  <button
                    onClick={() => document.getElementById('file-input').click()}
                    className="bg-cyan-500 hover:bg-cyan-400 text-white px-8 py-3 rounded-full font-medium transition-colors disabled:opacity-50 shadow-md"
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
            ) : (
              <div className="space-y-6">
                <div className="p-8 rounded-2xl border-2 border-white/20">
                  <div className="flex items-center mb-6">
                    <Search className="h-6 w-6 text-cyan-400 mr-3" />
                    <h2 className="text-xl font-semibold text-white">Check APK Link</h2>
                  </div>
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Paste APK link from Play Store..."
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="w-full bg-white/5 border border-white/20 text-white rounded-full p-4 pl-6 pr-28 transition-colors focus:outline-none focus:border-cyan-400"
                    />
                    <button
                      onClick={handleLinkCheck}
                      className="absolute right-2 top-2 bg-cyan-500 hover:bg-cyan-400 text-white px-6 py-2 rounded-full font-medium transition-colors disabled:opacity-50"
                      disabled={loading}
                    >
                      {loading ? 'Checking...' : 'Check'}
                    </button>
                  </div>
                </div>
              </div>
            )}
            
            {error && (
              <div className="mt-4 bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-red-200 text-sm">
                <AlertTriangle className="inline h-5 w-5 mr-2 text-red-400" />
                {error}
              </div>
            )}
          </div>
        ) : (
          /* Results Section */
          <div className="bg-white/5 backdrop-blur-lg rounded-3xl border border-white/10 p-8 shadow-2xl">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold text-white">Analysis Result</h2>
              <button
                onClick={() => setResult(null)}
                className="text-blue-200 hover:text-white transition-colors"
              >
                Analyze Another
              </button>
            </div>

            {/* Summary */}
            <div className="grid md:grid-cols-3 gap-6 mb-8">
              <div className="bg-white/5 rounded-2xl p-6 text-center border border-white/10">
                <FileText className="h-8 w-8 text-blue-400 mx-auto mb-2" />
                <h3 className="text-white font-medium truncate">
                  {result.apkMeta?.packageName || result.appInfo?.title}
                </h3>
                <p className="text-blue-200 text-sm">
                  {result.apkMeta?.versionName ? `v${result.apkMeta?.versionName}` : result.appInfo?.developer}
                </p>
              </div>
              <div
                className={`bg-white/5 rounded-2xl p-6 text-center border-2 transition-all duration-300 ${
                  result.analysis ? getRiskColor(riskScore) : 'border-green-200'
                }`}
              >
                <div
                  className={`mx-auto w-16 h-16 rounded-full flex items-center justify-center mb-3 border-2 ${
                    result.analysis ? getRiskColor(riskScore) : 'bg-green-400/20 text-green-600 border-green-200'
                  }`}
                >
                  {result.analysis ? (
                    riskScore >= 70 ? (
                      <XCircle className="h-8 w-8" />
                    ) : riskScore >= 40 ? (
                      <AlertTriangle className="h-8 w-8" />
                    ) : (
                      <CheckCircle className="h-8 w-8" />
                    )
                  ) : (
                    <CheckCircle className="h-8 w-8" />
                  )}
                </div>
                <h3 className="text-white font-medium">
                  {result.analysis ? getRiskLevel(riskScore) : 'Official Source'}
                </h3>
                <p className="text-blue-200 text-sm">
                  {result.analysis ? `Score: ${riskScore}/100` : `Trust Level: High`}
                </p>
              </div>
              <div className="bg-white/5 rounded-2xl p-6 text-center border border-white/10">
                <Shield className="h-8 w-8 text-green-400 mx-auto mb-2" />
                <h3 className="text-white font-medium">
                  {totalThreats || result.appInfo?.score}
                </h3>
                <p className="text-blue-200 text-sm">
                  {result.analysis ? 'Threats Detected' : 'Play Store Score'}
                </p>
              </div>
            </div>

            {/* Detailed Results Section */}
            {result.analysis ? (
              <div className="space-y-6">
                {riskReasons.length > 0 && (
                  <div className="mt-6 bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-red-200 text-sm">
                    <AlertTriangle className="inline h-5 w-5 mr-2 text-red-400" />
                    <span className="font-semibold">Security Warnings:</span>
                    {riskReasons.map((r, i) => (
                      <div key={i}>• {r}</div>
                    ))}
                  </div>
                )}
                <div className="grid md:grid-cols-2 gap-6">
                  {/* Certificate */}
                  <div className="bg-white/5 rounded-2xl p-6 border border-white/10">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                      <Key className="h-5 w-5 text-cyan-400 mr-2" /> Certificate
                    </h3>
                    <ul className="text-sm text-blue-200 space-y-2">
                      <li className="flex justify-between items-center"><span className="font-medium">Issuer:</span><span className="truncate">{result.certificate?.issuerCN}</span></li>
                      <li className="flex justify-between items-center"><span className="font-medium">Subject:</span><span className="truncate">{result.certificate?.subjectCN}</span></li>
                      <li className="flex justify-between items-center"><span className="font-medium">Algorithm:</span><span>{result.certificate?.signatureAlgorithm}</span></li>
                      <li className="flex justify-between items-center"><span className="font-medium">Self-Signed:</span><span>{result.certificate?.isSelfSigned ? 'Yes' : 'No'}</span></li>
                    </ul>
                  </div>
                  {/* Permissions */}
                  <div className="bg-white/5 rounded-2xl p-6 border border-white/10">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                      <Users className="h-5 w-5 text-cyan-400 mr-2" /> Permissions
                    </h3>
                    <ul className="text-sm text-blue-200 space-y-2">
                      <li className="flex justify-between items-center"><span className="font-medium">Total:</span><span>{result.permissions?.totalPermissions}</span></li>
                      <li className="flex justify-between items-center"><span className="font-medium">Suspicious:</span><span>{result.permissions?.flaggedSuspicious.length}</span></li>
                      <li className="flex justify-between items-center"><span className="font-medium">Network Access:</span><span>{result.permissions?.allPermissions.includes('android.permission.INTERNET') ? 'Yes' : 'No'}</span></li>
                    </ul>
                  </div>
                </div>
                {result.permissions?.flaggedSuspicious.length > 0 && (
                  <div className="bg-white/5 rounded-2xl p-6 border border-white/10">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                      <AlertTriangle className="h-5 w-5 text-red-400 mr-2" /> Suspicious Permissions
                    </h3>
                    <ul className="text-sm text-red-200 space-y-2">
                      {result.permissions?.flaggedSuspicious.map((p, i) => (
                        <li key={i}>{p}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              // Link Checker Results
              <div className="bg-white/5 rounded-2xl p-6 border border-white/10">
                <h3 className="text-xl font-semibold text-white mb-4 flex items-center">
                  <ExternalLink className="h-6 w-6 text-cyan-400 mr-2" /> Link Check Results
                </h3>
                {result.success ? (
                  <div className="space-y-3 text-blue-200">
                    <div className="font-bold text-white">{result.appInfo.title}</div>
                    <div>Developer: {result.appInfo.developer}</div>
                    <div>Version: {result.appInfo.version}</div>
                    <div>Installs: {result.appInfo.installs}</div>
                    <div>Score: {result.appInfo.score}</div>
                    <a href={result.appInfo.link} target="_blank" className="text-cyan-400 hover:text-cyan-300 underline flex items-center">
                      View on Play Store <ExternalLink className="h-4 w-4 ml-1" />
                    </a>
                  </div>
                ) : (
                  <div>
                    <p className="text-red-400 font-semibold mb-2">{result.message}</p>
                    <a href={result.officialLink} target="_blank" className="text-cyan-400 hover:text-cyan-300 underline flex items-center">
                      Find Official App Here <ExternalLink className="h-4 w-4 ml-1" />
                    </a>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Loading Overlay */}
        {loading && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-white/10 border border-white/20 rounded-2xl p-8 text-center shadow-lg">
              <Loader2 className="h-12 w-12 text-cyan-400 animate-spin mx-auto mb-3" />
              <p className="text-white">
                {viewMode === 'upload' ? 'Analyzing APK...' : 'Checking Link...'}
              </p>
              <p className="text-blue-200 text-sm">
                This may take a few moments
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}