import { Plus, ShieldCheck } from "lucide-react";
import type { AuditSummary } from "../lib/types";
import { gradeColor, totalIssues } from "../lib/severity";
import { formatDateShort, hostname } from "../lib/format";
import { ThemeToggle } from "./ThemeToggle";
import { CatalogButton } from "./CatalogButton";

export function Sidebar({
  audits,
  activeId,
  onNew,
  onSelect,
}: {
  audits: AuditSummary[];
  activeId: string | null;
  onNew: () => void;
  onSelect: (id: string) => void;
}) {
  return (
    <aside
      className="flex h-full w-64 shrink-0 flex-col border-r"
      style={{
        borderColor: "var(--border-subtle)",
        backgroundColor: "var(--bg-surface)",
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-4">
        <ShieldCheck className="h-6 w-6" style={{ color: "var(--accent-text)" }} />
        <span
          className="font-semibold tracking-tight"
          style={{ color: "var(--text-primary)" }}
        >
          VibeAuditt
        </span>
      </div>

      {/* Nueva auditoría */}
      <div className="px-3">
        <button
          type="button"
          onClick={onNew}
          className="inline-flex w-full items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-medium transition-opacity hover:opacity-90"
          style={{
            backgroundColor: "var(--accent-primary)",
            color: "var(--accent-primary-fg)",
          }}
        >
          <Plus className="h-4 w-4" />
          Nueva auditoría
        </button>
      </div>

      {/* Histórico */}
      <div className="mt-5 flex-1 overflow-y-auto px-3">
        <div
          className="px-1 pb-2 text-xs font-semibold uppercase tracking-wider"
          style={{ color: "var(--text-muted)" }}
        >
          Histórico
        </div>

        {audits.length === 0 ? (
          <p
            className="px-1 py-3 text-sm leading-relaxed"
            style={{ color: "var(--text-muted)" }}
          >
            Aún no hay auditorías. Lanza la primera.
          </p>
        ) : (
          <ul className="space-y-1">
            {audits.map((a) => {
              const active = a.id === activeId;
              return (
                <li key={a.id}>
                  <button
                    type="button"
                    onClick={() => onSelect(a.id)}
                    className="flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-left transition-colors hover:bg-[var(--bg-elevated)]"
                    style={{
                      backgroundColor: active ? "var(--bg-elevated)" : "transparent",
                    }}
                  >
                    <span
                      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-xs font-bold"
                      style={{
                        backgroundColor: "var(--bg-base)",
                        color: gradeColor(a.grade),
                        border: `1px solid ${gradeColor(a.grade)}`,
                      }}
                    >
                      {a.grade}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span
                        className="block truncate text-sm"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {hostname(a.url)}
                      </span>
                      <span
                        className="block text-xs"
                        style={{ color: "var(--text-muted)" }}
                      >
                        {formatDateShort(a.createdAt)} · {totalIssues(a.counts)} hallazgos
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Catálogo + Footer */}
      <div className="border-t pt-3" style={{ borderColor: "var(--border-subtle)" }}>
        <CatalogButton />
        <div className="flex items-center justify-between px-4 py-2">
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            v0.1.0
          </span>
          <ThemeToggle />
        </div>
      </div>
    </aside>
  );
}
