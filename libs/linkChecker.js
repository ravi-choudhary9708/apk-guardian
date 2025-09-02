import gplay from "google-play-scraper";

/**
 * Connects to the VirusTotal API to check the URL for known malicious content.
 * @param {string} apkUrl The URL of the APK to scan.
 * @returns {Promise<object>} An object with the scan status and details.
 */
const performMalwareScan = async (apkUrl) => {
  const apiKey = '0b0adef5fce0170e207efa2365d3dcf383e96100152b6e597c29c91a80c9507a';
  const apiUrl = `https://www.virustotal.com/api/v3/urls`;

  try {
    const formData = new URLSearchParams();
    formData.append('url', apkUrl);
    
    // Submit the URL for analysis
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: formData.toString()
    });
    const result = await response.json();

    if (!response.ok) {
        return { status: "Error", details: `API Error: ${result.error.message}` };
    }

    // Wait for the analysis to complete (simplified polling)
    const reportUrl = `https://www.virustotal.com/api/v3/analyses/${result.data.id}`;
    let analysisResult;
    let attempts = 0;
    const maxAttempts = 10;
    const delay = ms => new Promise(res => setTimeout(res, ms));

    while (attempts < maxAttempts) {
        await delay(3000); // Wait 3 seconds before polling
        const reportResponse = await fetch(reportUrl, {
            headers: { 'x-apikey': apiKey }
        });
        analysisResult = await reportResponse.json();
        
        if (analysisResult.data.attributes.status === 'completed') {
            break;
        }
        attempts++;
    }

    const maliciousCount = analysisResult.data.attributes.stats.malicious || 0;
    const suspiciousCount = analysisResult.data.attributes.stats.suspicious || 0;
    const totalThreats = maliciousCount + suspiciousCount;

    if (totalThreats > 0) {
       return { status: "Flagged", details: `${totalThreats} security vendors flagged this URL.` };
    } else {
       return { status: "Clean", details: "No threats detected by security vendors." };
    }

  } catch (error) {
    return { status: "Error", details: `Malware scan failed: ${error.message}` };
  }
};

/**
 * Extracts a package name from a given URL.
 * @param {string} url - The URL to parse.
 * @returns {string|null} The package name or null if not found.
 */
function extractPackageName(url) {
  try {
    const match = url.match(/id=([^&]+)/);
    return match ? match[1] : null;
  } catch (error) {
    console.error("Error extracting package name:", error);
    return null;
  }
}

/**
 * Checks and analyzes a given APK link against multiple sources.
 * @param {string} apkUrl The URL of the APK.
 * @returns {Promise<object>} An object containing the analysis results.
 */
export async function checkAPKLink(apkUrl) {
  try {
    const packageName = extractPackageName(apkUrl);
    if (!packageName) {
      return {
        success: false,
        authenticity: "unverified",
        message: "Package name not found in link. Cannot perform analysis.",
        checks: {
          playStore: { status: "skipped" },
          webSearch: { status: "skipped" },
          malwareScan: { status: "skipped" }
        }
      };
    }

    const results = {
      success: true,
      authenticity: "unverified",
      message: "Analysis complete.",
      appInfo: null,
      checks: {
        playStore: { status: "pending" },
        webSearch: { status: "pending" },
        malwareScan: { status: "pending" }
      }
    };

    // Layer 1: Check against Google Play Store
    let playData = null;
    try {
      playData = await gplay.app({ appId: packageName });
      if (playData) {
        results.checks.playStore = {
          status: "Found",
          message: "App found on Google Play Store.",
          data: {
            title: playData.title,
            developer: playData.developer,
            version: playData.version,
            installs: playData.installs,
            score: playData.score,
            icon: playData.icon,
            link: playData.url,
          }
        };
        results.authenticity = "verified";
        results.appInfo = results.checks.playStore.data;
      } else {
        results.checks.playStore = {
          status: "NotFound",
          message: "App not found on Google Play Store. Proceeding with other checks.",
          officialLink: `https://play.google.com/store/search?q=${packageName}&c=apps`,
        };
      }
    } catch (err) {
      results.checks.playStore = {
        status: "Error",
        message: "Error connecting to Play Store API.",
        error: err.message
      };
    }
    
    // Layer 2: Malware/Safety scan
    const malwareScanResult = await performMalwareScan(apkUrl);
    results.checks.malwareScan = {
      status: malwareScanResult.status,
      message: malwareScanResult.details,
    };

    // Final authenticity determination
    if (results.checks.malwareScan.status === "Flagged") {
        results.authenticity = "malicious";
        results.success = false;
        results.message = "Analysis flagged this link as malicious.";
    } else if (results.authenticity === "unverified") {
        results.success = false;
        results.message = "Analysis failed to verify the link. Exercise caution.";
    }

    return results;

  } catch (error) {
    return {
      success: false,
      authenticity: "unknown",
      message: "An unexpected error occurred during analysis.",
      error: error.message,
    };
  }
}
