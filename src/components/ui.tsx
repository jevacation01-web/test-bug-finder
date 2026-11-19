import type { ReactNode } from "react";
import { SEVERITY_ORDER, type Severity } from "@/lib/scanner";

export const SEVERITY_META: Record<
  Severity,
  { label: string; text: string; bg: string; border: string; dot: string }
> = {
  critical: {
    label: "CRITICAL",
    text: "text-rose-300",
    bg: "bg-rose-500/10",
    border: "border-rose-500/40",
    dot: "bg-rose-500",
  },
  high: {
    label: "HIGH",
    text: "text-orange-300",
    bg: "bg-orange-500/10",
    border: "border-orange-500/40",
    dot: "bg-orange-400",
  },
  medium: {
    label: "MEDIUM",
    text: "text-amber-200",
    bg: "bg-amber-400/10",
    border: "border-amber-400/40",
    dot: "bg-amber-300",
  },
  low: {
    label: "LOW",
    text: "text-sky-300",
    bg: "bg-sky-500/10",
    border: "border-sky-500/40",
    dot: "bg-sky-400",
  },
  info: {
    label: "INFO",
    text: "text-slate-300",
    bg: "bg-slate-500/10",
    border: "border-slate-500/40",
    dot: "bg-slate-400",
  },
};

export function SeverityBadge({
  severity,
  points,
}: {
  severity: Severity;
  points?: number;
}) {
  const m = SEVERITY_META[severity];
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-0.5 font-mono-term text-[10px] font-bold tracking-widest ${m.bg} ${m.border} ${m.text}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
      {points !== undefined && (
        <span className="opacity-70">+{points}pt</span>
      )}
    </span>
  );
}

export function gradeColor(grade: string | null | undefined): string {
  if (!grade) return "text-slate-500";
  if (grade.startsWith("A")) return "text-emerald-400";
  if (grade === "B") return "text-lime-400";
  if (grade === "C") return "text-amber-400";
  if (grade === "D") return "text-orange-400";
  return "text-rose-500";
}

export function GradeRing({
  grade,
  score,
  size = 116,
}: {
  grade: string | null | undefined;
  score: number | null | undefined;
  size?: number;
}) {
  const pct = Math.max(0, Math.min(100, score ?? 0));
  const r = (size - 14) / 2;
  const c = 2 * Math.PI * r;
  const color =
    pct >= 84 ? "#34d399" : pct >= 58 ? "#fbbf24" : pct >= 42 ? "#fb923c" : "#f43f5e";
  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="rgba(148,163,184,0.15)"
          strokeWidth={9}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={9}
          strokeLinecap="round"
          strokeDasharray={`${(pct / 100) * c} ${c}`}
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span
          className={`font-mono-term text-3xl font-black leading-none ${gradeColor(grade)}`}
          style={{ textShadow: `0 0 18px currentColor` }}
        >
          {grade ?? "—"}
        </span>
        <span className="mt-1 font-mono-term text-[11px] text-slate-400">
          {score ?? 0}/100
        </span>
      </div>
    </div>
  );
}

export function CountsBar({
  counts,
}: {
  counts: Partial<Record<Severity, number>> | null | undefined;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {SEVERITY_ORDER.map((sev) => {
        const n = counts?.[sev] ?? 0;
        const m = SEVERITY_META[sev];
        return (
          <div
            key={sev}
            className={`flex items-center gap-1.5 rounded border px-2 py-1 font-mono-term text-xs ${
              n > 0 ? `${m.bg} ${m.border} ${m.text}` : "border-slate-800 text-slate-600"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${n > 0 ? m.dot : "bg-slate-700"}`} />
            <span className="font-bold">{n}</span>
            <span className="opacity-70">{m.label}</span>
          </div>
        );
      })}
    </div>
  );
}

export function SectionCard({
  title,
  icon,
  children,
  right,
}: {
  title: string;
  icon?: ReactNode;
  children: ReactNode;
  right?: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm">
      <header className="flex items-center justify-between gap-3 border-b border-slate-800/80 px-4 py-3">
        <h2 className="flex items-center gap-2 font-mono-term text-xs font-bold uppercase tracking-[0.2em] text-slate-400">
          {icon}
          {title}
        </h2>
        {right}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function LegalNote() {
  return (
    <p className="mx-auto max-w-3xl px-4 pb-8 text-center text-xs leading-relaxed text-slate-500">
      ⚖️ BountyHawk performs <span className="text-slate-400">passive reconnaissance only</span> —
      equivalent to visiting a page in a browser. Actively exploiting systems you do not own or
      have written permission to test is illegal under laws like the IT&nbsp;Act&nbsp;§66 (India),
      CFAA (US) and Computer Misuse Act (UK). Use this tool on your own infrastructure or
      authorized bug-bounty scopes only.
    </p>
  );
}
