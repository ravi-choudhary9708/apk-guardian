export function calculateRiskScore(analysis) {
  let score = 0;
  let reasons = [];

  
  // Certificate Check
  if (analysis.certificate.isSelfSigned) {
    score += 25;
    reasons.push("App is signed with a self-signed certificate.");
  }

  // VirusTotal Check
  if (analysis.virusTotal?.stats?.malicious > 0) {
    score += 50;
    reasons.push("VirusTotal flagged app as malicious.");
  } else if (analysis.virusTotal?.stats?.suspicious > 0) {
    score += 30;
    reasons.push("VirusTotal flagged app as suspicious.");
  }

  // Permissions Check
  if (analysis.permissions.flaggedSuspicious.length > 0) {
    score += 20;
    reasons.push("Suspicious permissions detected: " + analysis.permissions.flaggedSuspicious.join(", "));
  }

  // Network Analysis
  if (analysis.networkAnalysis.urls.length > 0 || analysis.networkAnalysis.ips.length > 0) {
    score += 20;
    reasons.push("App communicates with external servers.");
  }

  return { score, reasons };
}

