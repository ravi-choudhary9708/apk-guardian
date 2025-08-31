// utils/networkAnalyzer.js
import fs from "fs";
import apkParser3 from "apk-parser3";
import ApkReader from "node-apk-parser";

const URL_REGEX = /(https?:\/\/[^\s"']+)/g;
const IP_REGEX = /\b\d{1,3}(\.\d{1,3}){3}\b/g;

export async function analyzeNetwork(apkPath) {
     const reader = ApkReader.readFile(apkPath);
     const manifest = reader.readManifestSync();

  let urls = new Set();
  let ips = new Set();

  for (const file of reader.files || []) {
    if (file.name.endsWith(".dex") || file.name.endsWith(".smali")) {
      const content = file.getData().toString("utf8");

      const foundUrls = content.match(URL_REGEX) || [];
      const foundIps = content.match(IP_REGEX) || [];

      foundUrls.forEach((u) => urls.add(u));
      foundIps.forEach((i) => ips.add(i));
    }
  }

  return {
    urls: Array.from(urls),
    ips: Array.from(ips),
    status: urls.size > 0 || ips.size > 0 ? "Suspicious" : "Clean",
  };
}
