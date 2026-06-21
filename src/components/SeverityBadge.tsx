import type { Severity } from "../lib/types";
import { SEVERITY_LABEL, sevVars } from "../lib/severity";

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const v = sevVars(severity);
  return (
    <span
      className={
        "inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium " +
        (className ?? "")
      }
      style={{ backgroundColor: v.bg, color: v.color, borderColor: v.border }}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  );
}
