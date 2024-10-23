// src/app/api/markdown-files/route.ts
import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";

export async function GET() {
  const markdownDirectory = path.join(process.cwd(), "markdown");

  try {
    const files = await fs.promises.readdir(markdownDirectory);
    const markdownFiles = files.filter((file) => file.endsWith(".md"));
    return NextResponse.json(markdownFiles);
  } catch (error) {
    return NextResponse.error();
  }
}
