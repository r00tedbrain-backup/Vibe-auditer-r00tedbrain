import { useState, type ReactNode } from "react";
import { Check, ChevronDown, Copy, ShieldAlert, Target } from "lucide-react";
import type { Finding } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";

function ConfidenceChip({ finding }: { finding: Finding }) {
  if (finding.confidence === "confirmed") {
    return (
      <span
        className="inline-flex shrink-0 items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium"
        style={{
          backgroundColor: "var(--sev-critical-bg)",
          color: "var(--sev-critical)",
          borderColor: "var(--sev-critical-border)",
        }}
        title="Confirmado con una prueba de concepto no destructiva"
      >
        <Target className="h-3 w-3" />
        Explotable
      </span>
    );
  }
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 rounded-md border px-2 py-0.5 text-xs"
      style={{
        backgroundColor: "var(--bg-elevated)",
        color: "var(--text-muted)",
        borderColor: "var(--border-subtle)",
      }}
      title="Detectado por señales pasivas (no probado)"
    >
      Detectado
    </span>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(finding.prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard no disponible */
    }
  }

  return (
    <div
      className="overflow-hidden rounded-xl border"
      style={{
        borderColor: "var(--border-subtle)",
        backgroundColor: "var(--bg-surface)",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 p-4 text-left transition-colors hover:bg-[var(--bg-elevated)]"
      >
        <SeverityBadge severity={finding.severity} />
        <ConfidenceChip finding={finding} />
        <div className="min-w-0 flex-1">
          <div
            className="truncate font-medium"
            style={{ color: "var(--text-primary)" }}
          >
            {finding.title}
          </div>
          <div
            className="truncate text-sm"
            style={{ color: "var(--text-secondary)" }}
          >
            {finding.summary}
          </div>
        </div>
        <code
          className="hidden shrink-0 font-mono text-xs md:block"
          style={{ color: "var(--text-muted)" }}
        >
          {finding.id}
        </code>
        <ChevronDown
          className={"h-4 w-4 shrink-0 transition-transform " + (open ? "rotate-180" : "")}
          style={{ color: "var(--text-muted)" }}
        />
      </button>

      {open && (
        <div
          className="space-y-5 border-t px-4 py-5"
          style={{ borderColor: "var(--border-subtle)" }}
        >
          <Field label="Categoría">
            <span style={{ color: "var(--text-secondary)" }}>{finding.category}</span>
          </Field>

          {finding.evidence.length > 0 && (
            <Field label="Evidencia">
              <pre
                className="overflow-x-auto rounded-lg border p-3 font-mono text-xs leading-relaxed"
                style={{
                  borderColor: "var(--border-subtle)",
                  backgroundColor: "var(--bg-base)",
                  color: "var(--text-secondary)",
                }}
              >
                {finding.evidence.join("\n")}
              </pre>
            </Field>
          )}

          {finding.poc && (
            <Field label="Prueba de concepto (no destructiva)">
              <div
                className="flex gap-2 rounded-lg border p-3 text-sm"
                style={{
                  borderColor: "var(--sev-critical-border)",
                  backgroundColor: "var(--sev-critical-bg)",
                  color: "var(--text-primary)",
                }}
              >
                <ShieldAlert
                  className="mt-0.5 h-4 w-4 shrink-0"
                  style={{ color: "var(--sev-critical)" }}
                />
                <span>{finding.poc}</span>
              </div>
            </Field>
          )}

          {finding.attackChain.length > 0 && (
            <Field label="Cómo te explotaría un atacante">
              <ol
                className="space-y-2 rounded-lg border p-3"
                style={{
                  borderColor: "var(--sev-critical-border)",
                  backgroundColor: "var(--bg-base)",
                }}
              >
                {finding.attackChain.map((step, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2.5 text-sm"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <span
                      className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full font-mono text-xs font-semibold"
                      style={{
                        backgroundColor: "var(--sev-critical-bg)",
                        color: "var(--sev-critical)",
                      }}
                    >
                      {i + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </Field>
          )}

          <Field label="Cómo solucionarlo">
            <p
              className="text-sm leading-relaxed"
              style={{ color: "var(--text-secondary)" }}
            >
              {finding.remediation}
            </p>
          </Field>

          {finding.prompt && (
            <Field label="Prompt para tu IA">
              <div
                className="rounded-lg border"
                style={{
                  borderColor: "var(--border-subtle)",
                  backgroundColor: "var(--bg-base)",
                }}
              >
                <div
                  className="flex items-center justify-between border-b px-3 py-2"
                  style={{ borderColor: "var(--border-subtle)" }}
                >
                  <span
                    className="text-xs uppercase tracking-wider"
                    style={{ color: "var(--text-muted)" }}
                  >
                    Copiar y pegar en Cursor / Claude / v0
                  </span>
                  <button
                    type="button"
                    onClick={copyPrompt}
                    className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium transition-opacity hover:opacity-80"
                    style={{
                      backgroundColor: "var(--accent-primary)",
                      color: "var(--accent-primary-fg)",
                    }}
                  >
                    {copied ? (
                      <>
                        <Check className="h-3 w-3" /> Copiado
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" /> Copiar
                      </>
                    )}
                  </button>
                </div>
                <pre
                  className="overflow-x-auto p-3 font-mono text-xs leading-relaxed"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {finding.prompt}
                </pre>
              </div>
            </Field>
          )}

          {finding.references.length > 0 && (
            <Field label="Referencias">
              <ul className="space-y-1 text-sm">
                {finding.references.map((ref) => (
                  <li key={ref} style={{ color: "var(--accent-text)" }}>
                    {ref}
                  </li>
                ))}
              </ul>
            </Field>
          )}
        </div>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div
        className="mb-1.5 text-xs font-semibold uppercase tracking-wider"
        style={{ color: "var(--text-muted)" }}
      >
        {label}
      </div>
      {children}
    </div>
  );
}
