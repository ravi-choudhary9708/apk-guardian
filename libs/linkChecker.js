// libs/linkChecker.js
import gplay from "google-play-scraper";

// Extract package name from suspicious link
function extractPackageName(url) {
  try {
    const match = url.match(/com\.[a-zA-Z0-9_.]+/);
    return match ? match[0] : null;
  } catch {
    return null;
  }
}

export async function checkAPKLink(apkUrl) {
  try {
    const packageName = extractPackageName(apkUrl);
    if (!packageName) {
      return { success: false, message: "Package name not found in link." };
    }

    // 🔍 Check Play Store
    let playData;
    try {
      playData = await gplay.app({ appId: packageName });
    } catch (err) {
      playData = null; // Not found
    }

    if (!playData) {
      return {
        success: false,
        message: "This app is NOT found in Play Store. Possible fake.",
        officialLink: `https://play.google.com/store/search?q=${packageName}&c=apps`,
      };
    }

    // ✅ Build result if found
    return {
      success: true,
      authenticity: "verified",
      appInfo: {
        title: playData.title,
        developer: playData.developer,
        version: playData.version,
        installs: playData.installs,
        score: playData.score,
        icon: playData.icon,
        link: playData.url,
      },
    };
  } catch (error) {
    return {
      success: false,
      message: "Error checking link",
      error: error.message,
    };
  }
}
