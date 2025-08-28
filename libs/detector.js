// src/lib/detector.js
export function detectFake(apkMeta) {
  const suspicious = [];

  // Rule 1: Dangerous permissions
  const risky = ["SEND_SMS", "READ_SMS", "WRITE_SMS", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW"];
  if (apkMeta.permissions?.some((p) => risky.some((r) => p.includes(r)))) {
    suspicious.push("Requests dangerous permissions (SMS/Contacts).");
  }

 // Rule 2: Weird package name
if (
  typeof apkMeta.package === "string" &&
  (apkMeta.package.includes("com.update") || apkMeta.package.includes("com.bank.fake"))
) {
  suspicious.push("Suspicious package name.");
}
  // Rule 3: No version info
  if (!apkMeta.versionName) {
    suspicious.push("Missing version info.");
  }

  return {
    isFake: suspicious.length > 0,
    reasons: suspicious,
  };
}
