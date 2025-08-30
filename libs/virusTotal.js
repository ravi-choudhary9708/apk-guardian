export async function scanAndSummarizeWithVirusTotal(fileBuffer, fileName) {
  try {
    // Step 1: Upload file to VT
    const uploadRes = await fetch("https://www.virustotal.com/api/v3/files", {
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

    if (!uploadRes.ok) {
      throw new Error(`VirusTotal upload error: ${uploadRes.statusText}`);
    }

    const uploadData = await uploadRes.json();
    const analysisId = uploadData.data.id;

    // Step 2: Poll until completed
    let report;
    for (let i = 0; i < 10; i++) { // retry up to 10 times
      const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": process.env.VT_API_KEY },
      });

      if (!res.ok) throw new Error(`Failed to fetch report: ${res.statusText}`);

      report = await res.json();
      const status = report.data.attributes.status;

      if (status === "completed") break;
      await new Promise(r => setTimeout(r, 5000)); // wait 5s before retry
    }

    if (!report || report.data.attributes.status !== "completed") {
      throw new Error("VirusTotal analysis did not complete in time");
    }

    // Step 3: Summarize results
    const results = report.data.attributes.results;
    let malicious = 0, suspicious = 0, undetected = 0, harmless = 0;

    for (const engine in results) {
      const category = results[engine].category;
      if (category === "malicious") malicious++;
      else if (category === "suspicious") suspicious++;
      else if (category === "undetected") undetected++;
      else if (category === "harmless") harmless++;
    }

    return {
      analysisId,
      stats: {
        malicious,
        suspicious,
        harmless,
        undetected,
        total: malicious + suspicious + harmless + undetected,
      },
    };

  } catch (err) {
    console.error("VirusTotal scan error:", err);
    return null;
  }
}
