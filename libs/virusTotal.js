export async function scanWithVirusTotal(fileBuffer, fileName) {
  try {
    const res = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: {
        "x-apikey": process.env.VT_API_KEY,
      },
      body: (() => {
        const form = new FormData();
        form.append("file", new Blob([fileBuffer]), fileName);
        return form;
      })(),
    });

    if (!res.ok) {
      throw new Error(`VirusTotal API error: ${res.statusText}`);
    }

    const data = await res.json();
    return data; // will contain analysis_id
  } catch (err) {
    console.error("VirusTotal error:", err);
    return null;
  }
}

export async function getVirusTotalReport(analysisId) {
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        "x-apikey": process.env.VT_API_KEY,
      },
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch report: ${res.statusText}`);
    }

    const report = await res.json();
    return report;
  } catch (err) {
    console.error("VirusTotal report error:", err);
    return null;
  }
}

