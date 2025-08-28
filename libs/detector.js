// app/api/upload/route.js
import { NextResponse } from "next/server";
import ApkReader from "node-apk-parser";

// Fake detector utility (improved defensive coding)
export function detectFake(apkMeta) {
  const reasons = [];

  if (!apkMeta) {
    return { isFake: true, reasons: ["Could not parse APK metadata"] };
  }

  // Rule 1: Dangerous permissions
  const dangerousPermissions = ["SEND_SMS", "CALL_PHONE", "READ_CONTACTS"];
  const perms = apkMeta.usesPermissions || [];
  if (perms.some(p => dangerousPermissions.includes(p.name))) {
    reasons.push("Uses dangerous permissions");
  }

  // Rule 2: Suspicious package name
  const pkg = apkMeta.package || "";
  if (
    pkg.includes("hack") ||
    pkg.includes("malware") ||
    pkg.includes("test")
  ) {
    reasons.push("Suspicious package name");
  }

  // Rule 3: Missing version info
  if (!apkMeta.versionName || !apkMeta.versionCode) {
    reasons.push("Missing version info");
  }

  return {
    isFake: reasons.length > 0,
    reasons,
  };
}
