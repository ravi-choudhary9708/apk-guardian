// app/api/link-check/route.js
import { NextResponse } from "next/server";
import { checkAPKLink } from "@/libs/linkChecker"; // 🔹 import helper

export async function POST(req) {
  try {
    const body = await req.json();
    const { url } = body || {};

    if (!url) {
      return NextResponse.json(
        { success: false, message: "No APK URL provided" },
        { status: 400 }
      );
    }

    const result = await checkAPKLink(url);

    return NextResponse.json(result);
  } catch (err) {
    console.error("API Error:", err);
    return NextResponse.json(
      { success: false, message: "Internal Server Error", error: err.message },
      { status: 500 }
    );
  }
}
