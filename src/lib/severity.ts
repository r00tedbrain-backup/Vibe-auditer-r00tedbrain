import type { Severity, SeverityCounts } from "./types";

/** Orden de mayor a menor gravedad (para agrupar y ordenar findings). */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "clean",
];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Info",
  clean: "Correcto",
};

/** Variables CSS de color para una severidad. */
export function sevVars(s: Severity): { color: string; bg: string; border: string } {
  return {
    color: `var(--sev-${s})`,
    bg: `var(--sev-${s}-bg)`,
    border: `var(--sev-${s}-border)`,
  };
}

/** Color asociado a la letra de nota global. */
export function gradeColor(grade: string): string {
  const g = (grade || "").toUpperCase().charAt(0);
  if (g === "A") return "var(--sev-clean)";
  if (g === "B") return "var(--sev-low)";
  if (g === "C") return "var(--sev-medium)";
  if (g === "D") return "var(--sev-high)";
  return "var(--sev-critical)";
}

/** Severidades contables (excluye "clean"). */
export const COUNTABLE: Exclude<Severity, "clean">[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function totalIssues(c: SeverityCounts): number {
  return c.critical + c.high + c.medium + c.low + c.info;
}
