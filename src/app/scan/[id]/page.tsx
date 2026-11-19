import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { eq } from "drizzle-orm";
import {
  ArrowLeft,
  Braces,
  Bug,
  Crosshair,
  Flame,
  Fingerprint,
  Globe,
  ScrollText,
  ShieldCheck,
  Terminal,
  Wrench,
} from "lucide-react";
import { db } from "@/db";
import { findings as findingsTable, scans as scansTable } from "@/db/schema";
import type { Severity } from "@/lib/scanner";
import {
  CountsBar,
  GradeRing,
  LegalNote,
  SectionCard,
  SEVERITY_META,
} from "@/components/ui";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  return { title: `Scan #${id} Report — BountyHawk` };
}

const SEV_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export default async function ScanReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scanId = Number(id);
  if (!Number.isFinite(scanId)) notFound();

  let scan: Awaited<ReturnType<typeof loadScan>>[number] | undefined;
  let findingsList: Awaited<ReturnType<typeof loadFindings>> = [];
  try {
    [scan] = await loadScan(scanId);
    if (scan) findingsList = await loadFindings(scanId);
  } catch {
    /* db bootstrapping */
  }

  if (!scan) {
    return (
      <div className="mx-auto max-w-3xl px-4 py-24 text-center">
        <Bug className="mx-auto h-10 w-10 text-slate-600" />
        <h1 className="mt-4 font-mono-term text-lg font-bold text-slate-300">
          Scan #{id} not found
        </h1>
        <p className="mt-2 text-sm text-slate-500">
          Shayad yeh scan database mein hai hi nahi. Naya hunt start karo.
        </p>
        <Link
          href="/"
          className="mt-6 inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 font-mono-term text-sm font-black text-gray-950 hover:bg-emerald-400"
        >
          <Crosshair className="h-4 w-4" /> NEW SCAN
        </Link>
      </div>
    );
  }

  const failed = scan.status === "failed";

  return (
    <div className="hero-radial relative min-h-screen">
      <div className="bg-cyber-grid pointer-events-none absolute inset-0 opacity-40" />
      <div className="relative mx-auto max-w-6xl px-4 py-8">
        {/* Top bar */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 font-mono-term text-xs text-slate-400 transition hover:text-emerald-300"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> cd ../scan_history
          </Link>
          <span className="font-mono-term text-[11px] text-slate-600">
            report_id: #{scan.id} · generated{" "}
            {new Date(scan.createdAt).toLocaleString()}
          </span>
        </div>

        {/* Summary header */}
        <section className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/50 backdrop-blur">
          <div className="border-b border-slate-800/80 bg-gray-950/60 px-5 py-2.5 font-mono-term text-[11px] uppercase tracking-[0.25em] text-emerald-500/80">
            $ bountyhawk --report #{scan.id}
          </div>
          <div className="grid gap-6 p-5 sm:p-7 lg:grid-cols-[auto_1fr_auto]">
            <div className="flex items-center justify-center">
              <GradeRing
                grade={failed ? null : scan.grade}
                score={failed ? 0 : scan.score}
                size={132}
              />
            </div>

            <div className="min-w-0">
              <h1 className="truncate font-mono-term text-2xl font-black text-slate-100 sm:text-3xl">
                {scan.host}
              </h1>
              <p className="mt-1 truncate font-mono-term text-xs text-slate-500">
                target: {scan.url}
                {scan.finalUrl && scan.finalUrl !== scan.url && (
                  <> → {scan.finalUrl}</>
                )}
              </p>

              <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
                {failed ? (
                  <span className="rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 font-mono-term font-bold uppercase tracking-widest text-rose-300">
                    ✕ scan failed
                  </span>
                ) : (
                  <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 font-mono-term font-bold uppercase tracking-widest text-emerald-300">
                    ✓ scan complete
                  </span>
                )}
                {scan.statusCode && (
                  <span className="rounded border border-slate-700 bg-slate-800/60 px-2.5 py-1 font-mono-term text-slate-300">
                    HTTP {scan.statusCode}
                  </span>
                )}
              </div>

              {!failed && (
                <div className="mt-4">
                  <CountsBar counts={scan.counts ?? undefined} />
                </div>
              )}

              {failed && scan.error && (
                <p className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 font-mono-term text-xs leading-relaxed text-rose-200">
                  ↳ {scan.error}
                </p>
              )}

              {!failed && Array.isArray(scan.tech) && scan.tech.length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-1.5">
                  <Fingerprint className="h-3.5 w-3.5 text-cyan-400" />
                  {scan.tech.map((t) => (
                    <span
                      key={t}
                      className="rounded border border-cyan-500/25 bg-cyan-500/5 px-2 py-0.5 font-mono-term text-[10px] text-cyan-200"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex flex-row items-center justify-around gap-6 rounded-xl border border-slate-800/80 bg-gray-950/50 px-6 py-4 lg:flex-col lg:justify-center lg:gap-3">
              <div className="text-center">
                <p className="flex items-center justify-center gap-1 font-mono-term text-2xl font-black text-emerald-400 text-glow">
                  <Flame className="h-5 w-5" />
                  {scan.totalPoints.toLocaleString()}
                </p>
                <p className="font-mono-term text-[9px] uppercase tracking-[0.2em] text-slate-500">
                  bounty pts
                </p>
              </div>
              <div className="text-center">
                <p className="font-mono-term text-2xl font-black text-slate-100">
                  {scan.findingsCount}
                </p>
                <p className="font-mono-term text-[9px] uppercase tracking-[0.2em] text-slate-500">
                  findings
                </p>
              </div>
              <div className="text-center">
                <p className="font-mono-term text-2xl font-black text-cyan-400">
                  {(scan.headers ? Object.keys(scan.headers).length : 0)}
                </p>
                <p className="font-mono-term text-[9px] uppercase tracking-[0.2em] text-slate-500">
                  headers
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Findings */}
        {!failed && (
          <div className="mt-8 space-y-8">
            {findingsList.length === 0 ? (
              <SectionCard title="findings" icon={<Bug className="h-4 w-4 text-emerald-400" />}>
                <div className="py-10 text-center">
                  <ShieldCheck className="mx-auto h-10 w-10 text-emerald-400" />
                  <p className="mt-3 font-mono-term text-sm font-bold text-emerald-300">
                    GG — no vulnerabilities detected by passive recon
                  </p>
                  <p className="mt-1 text-sm text-slate-500">
                    Headers, cookies aur transport posture sab solid lag rahe hain. Active testing
                    (authz logic, injection) manually karni padegi.
                  </p>
                </div>
              </SectionCard>
            ) : (
              <div className="space-y-4">
                <h2 className="flex items-center gap-2 font-mono-term text-xs font-bold uppercase tracking-[0.25em] text-slate-400">
                  <Bug className="h-4 w-4 text-rose-400" />
                  vulnerability_findings ({findingsList.length})
                </h2>

                {findingsList.map((f) => {
                  const sev = f.severity as Severity;
                  const meta = SEVERITY_META[sev] ?? SEVERITY_META.info;
                  return (
                    <details
                      key={f.id}
                      className={`finding-card group overflow-hidden rounded-xl border bg-slate-900/50 backdrop-blur transition ${meta.border} hover:bg-slate-900/80`}
                      open={sev === "critical" || sev === "high"}
                    >
                      <summary className="flex cursor-pointer select-none items-center gap-3 px-4 py-3.5 sm:px-5">
                        <span className={`chevron font-mono-term text-sm ${meta.text}`}>▶</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityBadgeInline severity={sev} points={f.points} />
                            <span className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 font-mono-term text-[9px] uppercase tracking-wider text-slate-400">
                              {f.category}
                            </span>
                          </div>
                          <h3 className="mt-1.5 font-semibold leading-snug text-slate-100">
                            {f.title}
                          </h3>
                        </div>
                      </summary>

                      <div className="grid gap-5 border-t border-slate-800/80 px-4 py-5 sm:px-5 lg:grid-cols-2">
                        <div className="space-y-4">
                          <InfoBlock
                            icon={<ScrollText className="h-3.5 w-3.5 text-slate-400" />}
                            label="description"
                          >
                            <p className="text-sm leading-relaxed text-slate-300">
                              {f.description}
                            </p>
                          </InfoBlock>
                          <InfoBlock
                            icon={<Flame className="h-3.5 w-3.5 text-orange-400" />}
                            label="business impact"
                          >
                            <p className="text-sm leading-relaxed text-slate-300">{f.impact}</p>
                          </InfoBlock>
                          <InfoBlock
                            icon={<Wrench className="h-3.5 w-3.5 text-emerald-400" />}
                            label="remediation / fix"
                          >
                            <p className="text-sm leading-relaxed text-emerald-200/90">
                              {f.remediation}
                            </p>
                          </InfoBlock>
                        </div>
                        <InfoBlock
                          icon={<Terminal className="h-3.5 w-3.5 text-cyan-400" />}
                          label="proof of concept"
                        >
                          <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-gray-950 p-3 font-mono-term text-[11.5px] leading-relaxed text-cyan-200/90">
                            {f.poc}
                          </pre>
                        </InfoBlock>
                      </div>
                    </details>
                  );
                })}
              </div>
            )}

            {/* Raw headers */}
            {scan.headers && Object.keys(scan.headers).length > 0 && (
              <details className="group overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/50">
                <summary className="flex cursor-pointer select-none items-center gap-2 px-5 py-3.5 font-mono-term text-xs font-bold uppercase tracking-[0.2em] text-slate-400 hover:text-emerald-300">
                  <Braces className="h-4 w-4" />
                  raw response headers ({Object.keys(scan.headers).length})
                  <span className="chevron ml-auto font-mono-term">▶</span>
                </summary>
                <div className="border-t border-slate-800/80 p-4">
                  <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-gray-950 p-4 font-mono-term text-[11.5px] leading-relaxed text-slate-300">
                    {Object.entries(scan.headers)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </pre>
                </div>
              </details>
            )}
          </div>
        )}

        {/* CTA footer */}
        <div className="mt-10 flex flex-col items-center gap-4">
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-6 py-3 font-mono-term text-sm font-black text-gray-950 transition hover:bg-emerald-400"
          >
            <Globe className="h-4 w-4" /> SCAN ANOTHER TARGET
          </Link>
        </div>

        <div className="pt-10">
          <LegalNote />
        </div>
      </div>
    </div>
  );
}

function SeverityBadgeInline({
  severity,
  points,
}: {
  severity: Severity;
  points: number;
}) {
  const m = SEVERITY_META[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono-term text-[10px] font-bold tracking-widest ${m.bg} ${m.border} ${m.text}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label} +{points}pt
    </span>
  );
}

function InfoBlock({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <p className="mb-1.5 flex items-center gap-1.5 font-mono-term text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
        {icon}
        {label}
      </p>
      {children}
    </div>
  );
}

async function loadScan(id: number) {
  return db.select().from(scansTable).where(eq(scansTable.id, id)).limit(1);
}

async function loadFindings(scanId: number) {
  const rows = await db
    .select()
    .from(findingsTable)
    .where(eq(findingsTable.scanId, scanId));
  // Sort by severity rank then points desc (SQL ORDER BY on text enum would be brittle)
  return rows.sort(
    (a, b) =>
      (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) ||
      b.points - a.points
  );
}


