"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, Crosshair, Loader2, TerminalSquare } from "lucide-react";

const SCAN_STEPS = [
  "resolving target DNS…",
  "establishing TLS handshake…",
  "fetching response headers…",
  "probing plaintext HTTP listener…",
  "crawling robots.txt…",
  "auditing security headers (CSP / HSTS / XFO)…",
  "inspecting cookie attributes…",
  "fingerprinting technology stack…",
  "scoring vulnerabilities & bounty points…",
];

export default function ScanForm() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (busy || !url.trim()) return;
    setBusy(true);
    setError(null);
    setStepIdx(0);
    timerRef.current = setInterval(() => {
      setStepIdx((i) => Math.min(i + 1, SCAN_STEPS.length - 1));
    }, 900);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = (await res.json()) as {
        id?: number;
        error?: string;
        failed?: boolean;
      };
      if (!res.ok && !data.id) {
        setError(data.error ?? "Scan failed unexpectedly.");
        return;
      }
      router.push(`/scan/${data.id}`);
      router.refresh();
    } catch {
      setError("Network error talking to the scanner service.");
    } finally {
      if (timerRef.current) clearInterval(timerRef.current);
      setBusy(false);
    }
  }

  return (
    <div className="w-full max-w-2xl">
      <form onSubmit={handleSubmit} className="relative">
        <div className="flex flex-col gap-2 rounded-xl border border-slate-700/80 bg-slate-900/70 p-2 shadow-2xl shadow-emerald-500/5 backdrop-blur sm:flex-row">
          <div className="flex flex-1 items-center gap-2 px-3">
            <span className="font-mono-term text-sm font-bold text-emerald-400">
              https://
            </span>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={busy}
              placeholder="victim-site.com   ← apni website dalo"
              spellCheck={false}
              autoCapitalize="none"
              className="w-full bg-transparent py-2.5 font-mono-term text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none disabled:opacity-60"
            />
          </div>
          <button
            type="submit"
            disabled={busy || !url.trim()}
            className="group flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-6 py-2.5 font-mono-term text-sm font-black text-gray-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                SCANNING
              </>
            ) : (
              <>
                <Crosshair className="h-4 w-4" />
                RUN FULL SCAN
              </>
            )}
          </button>
        </div>

        {/* Live terminal feed */}
        {busy && (
          <div className="relative mt-3 overflow-hidden rounded-lg border border-emerald-500/25 bg-gray-950/90 p-3 box-glow">
            <div className="pointer-events-none absolute inset-x-0 top-0 h-8 bg-gradient-to-b from-emerald-400/10 to-transparent animate-scanline" />
            <div className="mb-2 flex items-center gap-2 font-mono-term text-[10px] uppercase tracking-widest text-emerald-500/80">
              <TerminalSquare className="h-3 w-3" />
              live recon feed
            </div>
            <ol className="space-y-1 font-mono-term text-xs">
              {SCAN_STEPS.slice(0, stepIdx + 1).map((s, i) => {
                const done = i < stepIdx;
                const active = i === stepIdx;
                return (
                  <li key={s} className="flex items-center gap-2">
                    <span
                      className={
                        done
                          ? "text-emerald-400"
                          : active
                            ? "text-cyan-300 animate-pulse-dot"
                            : "text-slate-600"
                      }
                    >
                      {done ? "[✓]" : active ? "[►]" : "[ ]"}
                    </span>
                    <span className={done ? "text-slate-500 line-through decoration-emerald-500/40" : active ? "text-slate-200" : "text-slate-600"}>
                      {s}
                    </span>
                  </li>
                );
              })}
            </ol>
            <div className={`mt-2 font-mono-term text-xs ${stepIdx >= SCAN_STEPS.length - 1 ? "cursor-blink text-slate-400" : "text-slate-600"}`}>
              $ bountyhawk --target {url || "…"}
            </div>
          </div>
        )}

        {error && (
          <div className="mt-3 flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            <div className="font-mono-term text-xs leading-relaxed text-rose-200">
              <p className="font-bold uppercase tracking-widest text-rose-400">
                scan aborted
              </p>
              <p className="mt-1">{error}</p>
            </div>
          </div>
        )}
      </form>

      {!busy && (
        <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
          <span className="font-mono-term text-[11px] text-slate-600">try:</span>
          {["example.com", "testphp.vulnweb.com", "wikipedia.org"].map((t) => (
            <button
              key={t}
              onClick={() => setUrl(t)}
              className="rounded-full border border-slate-700/80 bg-slate-900/60 px-3 py-1 font-mono-term text-[11px] text-slate-400 transition hover:border-emerald-500/50 hover:text-emerald-300"
            >
              {t}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
