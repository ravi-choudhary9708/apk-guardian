import { NextResponse } from "next/server";
import { detectFake } from "@/libs/detector";
import dbConnect from "@/libs/db";
import ScanResult from "@/models/ScanResult";

export async function POST(req) {
  try {
    const { filePath } = await req.json(); // frontend se file ka path aayega

    // DB connect
    await dbConnect();

    // APK analyze
    const result = await detectFake(filePath);

    // Save to MongoDB
    const saved = await ScanResult.create(result);

    return NextResponse.json({ success: true, data: saved });
  } catch (err) {
    console.error("APK analysis failed:", err);
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
