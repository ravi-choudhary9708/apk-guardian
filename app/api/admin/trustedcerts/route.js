// app/api/admin/trustedcerts/route.js
import { NextResponse } from "next/server";
import dbConnect from "@/libs/db";
import TrustedCert from "@/models/TrustedCert";

export async function POST(req) {
  try {
    await dbConnect();
    const body = await req.json();

    const {
      bankName,
      packageNames,
      certFingerprint,
      issuer,
      subject,
      validFrom,
      validTo,
      notes,
      addedBy,
    } = body;

    // Insert into DB
    const newCert = await TrustedCert.create({
      bankName,
      packageNames,
      certFingerprint,
      issuer,
      subject,
      validFrom,
      validTo,
      notes,
      addedBy,
    });

    return NextResponse.json(
      { message: "Trusted certificate added successfully", cert: newCert },
      { status: 201 }
    );
  } catch (error) {
    console.error("Error adding trusted cert:", error);
    return NextResponse.json(
      { error: "Failed to add trusted certificate", details: error.message },
      { status: 500 }
    );
  }
}
