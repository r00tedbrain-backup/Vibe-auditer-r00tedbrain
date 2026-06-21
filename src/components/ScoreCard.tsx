import type { AuditReport } from "../lib/types";
import { COUNTABLE, gradeColor, SEVERITY_LABEL } from "../lib/severity";

export function ScoreCard({ report }: { report: AuditReport }) {
  const gc = gradeColor(report.grade);
  return (
    <div
      className="rounded-xl border p-6"
      style={{
        borderColor: "var(--border-subtle)",
        backgroundColor: "var(--bg-surface)",
      }}
    >
      <div className="flex flex-col gap-6 lg:flex-row lg:items-center">
        {/* Letra + score */}
        <div className="flex items-center gap-4">
          <div
            className="flex h-20 w-20 items-center justify-center rounded-2xl text-4xl font-bold tabular-nums"
            style={{
              backgroundColor: "var(--bg-elevated)",
              color: gc,
              border: `1px solid ${gc}`,
            }}
          >
            {report.grade}
          </div>
          <div>
            <div
              className="text-3xl font-semibold tabular-nums"
              style={{ color: "var(--text-primary)" }}
            >
              {report.score}
              <span className="text-lg" style={{ color: "var(--text-muted)" }}>
                /100
              </span>
            </div>
            <div className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Puntuación de seguridad
            </div>
          </div>
        </div>

        {/* Contadores por severidad */}
        <div className="grid flex-1 grid-cols-3 gap-2 sm:grid-cols-5">
          {COUNTABLE.map((s) => (
            <div
              key={s}
              className="rounded-lg border p-3 text-center"
              style={{
                borderColor: "var(--border-subtle)",
                backgroundColor: "var(--bg-base)",
              }}
            >
              <div
                className="text-2xl font-semibold tabular-nums"
                style={{ color: `var(--sev-${s})` }}
              >
                {report.counts[s]}
              </div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                {SEVERITY_LABEL[s]}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
