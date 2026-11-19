import Link from "next/link";
import {
  Activity,
  ArrowRight,
  Crosshair,
  Database,
  FileSearch,
  Fingerprint,
  Globe,
  ShieldAlert,
  ShieldCheck,
  Trophy,
} from "lucide-react";
import ScanForm from "@/components/scan-form";
import { LegalNote } from "@/components/ui";
import { db } from "@/db";
import { scans as scansTable } from "@/db/schema";
import { desc, sql } from "drizzle-orm";

export const dynamic = "force-dynamic";

const FEATURES = [
  {
    icon: ShieldAlert,
    title: "Security Header Audit",
    desc: "CSP, HSTS, X-Frame-Options, cookie flags, CORP/COOP — scored against Mozilla Observatory baselines.",
  },
  {
    icon: Fingerprint,
    title: "Tech Stack Fingerprinting",
    desc: "Detect WordPress, Next.js, nginx versions, Cloudflare, jQuery & more — exactly what an attacker sees.",
  },
  {
    icon: Globe,
    title: "Transport & TLS Checks",
    desc: "HTTPS enforcement, plaintext HTTP listeners on port 80, mixed-content references in the page body.",
  },
  {
    icon: FileSearch,
    title: "Passive Recon Sweep",
    desc: "robots.txt treasure-maps, version disclosure, error-banner intel, sensitive path enumeration.",
  },
  {
    icon: Crosshair,
    title: "Exploit-Style PoCs",
    desc: "Every finding ships with a real Proof-of-Concept write-up — clickjacking pages, MITM captures, XSS chains.",
  },
  {
    icon: Database,
    title: "Persistent Scan History",
    desc: "All scans stored in PostgreSQL with severity counts, grades and bounty points. Track your progress over time.",
  },
];

const STEPS = [
  { n: "01", t: "Drop a target", d: "Apni website ka URL paste karo — https:// ke bina bhi chalega." },
  { n: "02", t: "Full recon runs", d: "Headers, cookies, TLS, robots.txt, tech stack — sab passive scan hota hai." },
  { n: "03", t: "Read the report", d: "Har bug ke saath severity, CVSS-style points, PoC aur fix milta hai." },
];

async function getStats() {
  try {
    const rows = await db
      .select({
        count: sql<number>`count(*)::int`,
        findings: sql<number>`coalesce(sum(${scansTable.findingsCount}),0)::int`,
        points: sql<number>`coalesce(sum(${scansTable.totalPoints}),0)::int`,
      })
      .from(scansTable);
    return rows[0] ?? { count: 0, findings: 0, points: 0 };
  } catch {
    return { count: 0, findings: 0, points: 0 };
  }
}

export default async function HomePage() {
  const stats = await getStats();
  let recent: Awaited<ReturnType<typeof latestScans>> = [];
  try {
    recent = await latestScans();
  } catch {
    /* fresh DB */
  }

  return (
    <div className="hero-radial relative overflow-hidden">
      <div className="bg-cyber-grid pointer-events-none absolute inset-0 opacity-60" />

      {/* HERO */}
      <section className="relative mx-auto flex max-w-6xl flex-col items-center px-4 pb-16 pt-16 text-center sm:pt-24">
        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 font-mono-term text-[11px] font-bold uppercase tracking-[0.25em] text-emerald-300">
          <Activity className="h-3.5 w-3.5 animate-pulse-dot" />
          bug bounty recon engine v1.0
        </div>

        <h1 className="max-w-4xl font-mono-term text-4xl font-black leading-tight tracking-tight text-slate-100 sm:text-6xl">
          Koi bhi website dalo.
          <br />
          <span className="text-emerald-400 text-glow">Bugs dhundho.</span>{" "}
          <span className="bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">
            Exploit seekho.
          </span>
        </h1>

        <p className="mt-5 max-w-2xl text-sm leading-relaxed text-slate-400 sm:text-base">
          BountyHawk runs a <span className="text-slate-200">full passive security scan</span> on any
          target — auditing headers, cookies, TLS posture, exposed paths and the complete tech
          stack — then writes you a bounty-grade report with{" "}
          <span className="text-emerald-300">Proof-of-Concept exploits</span> and fixes for every bug.
        </p>

        <div className="mt-10 flex w-full justify-center">
          <ScanForm />
        </div>

        {/* Stats strip */}
        <div className="mt-14 grid w-full max-w-3xl grid-cols-3 divide-x divide-slate-800/80 rounded-xl border border-slate-800/80 bg-slate-900/40 backdrop-blur">
          {[
            { label: "scans executed", value: stats.count },
            { label: "bugs discovered", value: stats.findings },
            { label: "bounty points", value: stats.points.toLocaleString() },
          ].map((s) => (
            <div key={s.label} className="px-4 py-5">
              <p className="font-mono-term text-2xl font-black text-emerald-400 sm:text-3xl">
                {s.value}
              </p>
              <p className="mt-1 font-mono-term text-[10px] uppercase tracking-[0.2em] text-slate-500">
                {s.label}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* RECENT SCANS */}
      {recent.length > 0 && (
        <section className="relative mx-auto max-w-6xl px-4 pb-16">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-mono-term text-xs font-bold uppercase tracking-[0.25em] text-slate-400">
              // latest_hunts
            </h2>
            <Link
              href="/dashboard"
              className="flex items-center gap-1 font-mono-term text-xs text-emerald-400 hover:text-emerald-300"
            >
              view all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {recent.map((r) => (
              <Link
                key={r.id}
                href={`/scan/${r.id}`}
                className="group rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 transition hover:border-emerald-500/40 hover:bg-slate-900/70"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono-term text-sm font-bold text-slate-200 group-hover:text-emerald-300">
                    {r.host}
                  </span>
                  {r.status === "completed" ? (
                    <span className="font-mono-term text-lg font-black text-emerald-400">
                      {r.grade ?? "—"}
                    </span>
                  ) : (
                    <span className="font-mono-term text-[10px] font-bold uppercase text-rose-400">
                      failed
                    </span>
                  )}
                </div>
                <p className="mt-2 font-mono-term text-[11px] text-slate-500">
                  {r.findingsCount} bugs · {r.totalPoints.toLocaleString()} pts ·{" "}
                  {new Date(r.createdAt).toLocaleDateString()}
                </p>
              </Link>
            ))}
          </div>
        </section>
      )}

      {/* HOW IT WORKS */}
      <section className="relative mx-auto max-w-6xl px-4 pb-16">
        <h2 className="mb-6 text-center font-mono-term text-xs font-bold uppercase tracking-[0.3em] text-slate-400">
          // how_it_works
        </h2>
        <div className="grid gap-4 sm:grid-cols-3">
          {STEPS.map((s) => (
            <div
              key={s.n}
              className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-5"
            >
              <span className="font-mono-term text-3xl font-black text-emerald-500/30">
                {s.n}
              </span>
              <h3 className="mt-2 font-bold text-slate-100">{s.t}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{s.d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* FEATURES */}
      <section className="relative mx-auto max-w-6xl px-4 pb-16">
        <h2 className="mb-6 text-center font-mono-term text-xs font-bold uppercase tracking-[0.3em] text-slate-400">
          // arsenal
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="group rounded-xl border border-slate-800/80 bg-slate-900/40 p-5 transition hover:border-emerald-500/30"
            >
              <f.icon className="h-6 w-6 text-emerald-400 transition group-hover:scale-110" />
              <h3 className="mt-3 font-bold text-slate-100">{f.title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ETHICS CTA */}
      <section className="relative mx-auto max-w-4xl px-4 pb-16">
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-6 text-center box-glow">
          <ShieldCheck className="mx-auto h-8 w-8 text-cyan-400" />
          <h3 className="mt-3 font-mono-term text-lg font-bold text-slate-100">
            Ethical hacking only.
          </h3>
          <p className="mx-auto mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">
            Yeh tool sirf <span className="text-slate-200">passive recon</span> karta hai (browser
            jaisa GET request). Real bug bounty programs — HackerOne, Bugcrowd, apni company ka
            VDP — inhi techniques par chalte hain. Bina permission kisi ki site attack karna{" "}
            <span className="text-rose-300">crime hai</span>, skill nahi.
          </p>
        </div>
      </section>

      <LegalNote />
    </div>
  );
}

async function latestScans() {
  return db.select().from(scansTable).orderBy(desc(scansTable.createdAt)).limit(6);
}
