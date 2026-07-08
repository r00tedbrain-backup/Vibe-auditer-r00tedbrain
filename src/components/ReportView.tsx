import { useMemo, useState } from "react";
import {
  Check,
  Copy,
  FileDown,
  Globe,
  Loader2,
  Plus,
  ScanSearch,
  Trash2,
  Zap,
} from "lucide-react";
import type { AuditReport, Finding, Severity } from "../lib/types";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "../lib/severity";
import { formatDate, formatDuration } from "../lib/format";
import { ScoreCard } from "./ScoreCard";
import { FindingCard } from "./FindingCard";

export function ReportView({
  report,
  onNew,
  onDelete,
}: {
  report: AuditReport;
  onNew: () => void;
  onDelete: (id: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    setExporting(true);
    try {
      const { saveReportPdf } = await import("../lib/catalog");
      await saveReportPdf(report);
    } catch (e) {
      console.error("PDF export failed:", e);
      alert(
        "No se pudo generar el PDF: " +
          (typeof e === "string" ? e : "error interno"),
      );
    } finally {
      setExporting(false);
    }
  }

  const grouped = useMemo(() => {
    const g = {} as Record<Severity, Finding[]>;
    for (const sev of SEVERITY_ORDER) g[sev] = [];
    for (const f of report.findings) (g[f.severity] ??= []).push(f);
    return g;
  }, [report]);

  async function copyAllPrompts() {
    const text = report.findings
      .filter((f) => f.prompt)
      .map((f) => `## ${f.title}\n${f.prompt}`)
      .join("\n\n");
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* noop */
    }
  }

  const hasIssues = report.findings.some((f) => f.severity !== "clean");

  return (
    <div className="mx-auto max-w-4xl px-6 py-8 va-fade-in">
      {/* Cabecera */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 shrink-0" style={{ color: "var(--text-muted)" }} />
            <code
              className="truncate font-mono text-sm"
              style={{ color: "var(--text-primary)" }}
            >
              {report.url}
            </code>
          </div>
          <div
            className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs"
            style={{ color: "var(--text-muted)" }}
          >
            <span>{formatDate(report.createdAt)}</span>
            <span>·</span>
            <span>{formatDuration(report.durationMs)}</span>
            <span>·</span>
            <span className="inline-flex items-center gap-1">
              {report.mode === "active" ? (
                <>
                  <Zap className="h-3 w-3" /> Activo
                </>
              ) : (
                <>
                  <ScanSearch className="h-3 w-3" /> Pasivo
                </>
              )}
            </span>
            <span>·</span>
            <span>{report.checksRun} checks</span>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={handleExport}
            disabled={exporting}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-[var(--bg-elevated)] disabled:opacity-60"
            style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}
          >
            {exporting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FileDown className="h-4 w-4" />
            )}
            PDF
          </button>
          <button
            type="button"
            onClick={copyAllPrompts}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-[var(--bg-elevated)]"
            style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            {copied ? "Copiado" : "Copiar prompts"}
          </button>
          <button
            type="button"
            onClick={() => onDelete(report.id)}
            aria-label="Eliminar auditoría"
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-[var(--bg-elevated)]"
            style={{ borderColor: "var(--border-default)", color: "var(--text-secondary)" }}
          >
            <Trash2 className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={onNew}
            className="inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium transition-opacity hover:opacity-90"
            style={{
              backgroundColor: "var(--accent-primary)",
              color: "var(--accent-primary-fg)",
            }}
          >
            <Plus className="h-4 w-4" />
            Nueva
          </button>
        </div>
      </div>

      {/* Puntuación */}
      <div className="mt-6">
        <ScoreCard report={report} />
      </div>

      {/* Findings agrupados por severidad */}
      <div className="mt-8 space-y-8">
        {SEVERITY_ORDER.filter((s) => s !== "clean").map((sev) => {
          const items = grouped[sev];
          if (!items || items.length === 0) return null;
          return (
            <section key={sev}>
              <h2
                className="mb-3 flex items-center gap-2 text-lg font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                <span style={{ color: `var(--sev-${sev})` }}>
                  {SEVERITY_LABEL[sev]}
                </span>
                <span
                  className="rounded-full px-2 py-0.5 text-xs font-medium tabular-nums"
                  style={{
                    backgroundColor: `var(--sev-${sev}-bg)`,
                    color: `var(--sev-${sev})`,
                  }}
                >
                  {items.length}
                </span>
              </h2>
              <div className="space-y-2">
                {items.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            </section>
          );
        })}

        {/* Checks superados */}
        {grouped.clean && grouped.clean.length > 0 && (
          <section>
            <h2
              className="mb-3 flex items-center gap-2 text-lg font-semibold"
              style={{ color: "var(--text-primary)" }}
            >
              <span style={{ color: "var(--sev-clean)" }}>Correcto</span>
              <span
                className="rounded-full px-2 py-0.5 text-xs font-medium tabular-nums"
                style={{
                  backgroundColor: "var(--sev-clean-bg)",
                  color: "var(--sev-clean)",
                }}
              >
                {grouped.clean.length}
              </span>
            </h2>
            <div className="space-y-2">
              {grouped.clean.map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          </section>
        )}

        {!hasIssues && report.findings.length > 0 && (
          <div
            className="rounded-xl border p-6 text-center"
            style={{
              borderColor: "var(--sev-clean-border)",
              backgroundColor: "var(--sev-clean-bg)",
              color: "var(--text-primary)",
            }}
          >
            Sin vulnerabilidades detectadas. Buen trabajo.
          </div>
        )}
      </div>
    </div>
  );
}
