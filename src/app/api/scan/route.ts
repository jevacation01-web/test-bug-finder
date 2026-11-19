import { NextResponse } from "next/server";
import { db } from "@/db";
import { findings, scans } from "@/db/schema";
import { normalizeTarget, runScan } from "@/lib/scanner";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: Request) {
  let urlInput: string;
  try {
    const body = (await req.json()) as { url?: unknown };
    urlInput = typeof body.url === "string" ? body.url : "";
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body — expected { url: string }." },
      { status: 400 }
    );
  }

  // Fail fast on obviously invalid / forbidden targets
  try {
    normalizeTarget(urlInput);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Invalid target URL." },
      { status: 400 }
    );
  }

  const result = await runScan(urlInput);

  if (result.status === "failed") {
    // Still record failed attempts so the dashboard shows history
    try {
      const [row] = await db
        .insert(scans)
        .values({
          url: result.url,
          host: result.host,
          finalUrl: result.finalUrl,
          status: "failed",
          error: result.error ?? "Unknown failure",
          counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          tech: [],
          headers: {},
        })
        .returning();
      return NextResponse.json({ id: row.id, failed: true, error: result.error });
    } catch {
      return NextResponse.json(
        { error: result.error ?? "Scan failed." },
        { status: 502 }
      );
    }
  }

  const [row] = await db
    .insert(scans)
    .values({
      url: result.url,
      host: result.host,
      finalUrl: result.finalUrl,
      status: "completed",
      statusCode: result.statusCode ?? null,
      grade: result.grade ?? null,
      score: result.score ?? null,
      totalPoints: result.totalPoints ?? 0,
      findingsCount: result.findings.length,
      counts:
        result.counts ??
        ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 } as const),
      tech: result.tech ?? [],
      headers: result.headers ?? {},
    })
    .returning();

  if (result.findings.length > 0) {
    await db.insert(findings).values(
      result.findings.map((f) => ({
        scanId: row.id,
        slug: f.slug,
        severity: f.severity,
        title: f.title,
        category: f.category,
        description: f.description,
        impact: f.impact,
        poc: f.poc,
        remediation: f.remediation,
        points: f.points,
      }))
    );
  }

  return NextResponse.json({ id: row.id, grade: result.grade, score: result.score });
}
