// Contrato de datos compartido con el motor en Rust (serde, camelCase).
// Cualquier cambio aquí debe reflejarse en src-tauri/src/engine/types.rs

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "clean";

export type FindingStatus = "fail" | "warn" | "pass" | "info" | "error";

/** Nivel de confianza del hallazgo. */
export type Confidence =
  /** Detectado por señales pasivas (no probado). */
  | "detected"
  /** Confirmado con un PoC no destructivo (explotable de verdad). */
  | "confirmed";

/** Profundidad de la auditoría. */
export type AuditMode =
  /** Solo reconocimiento (GET + lectura de headers/bundles). */
  | "passive"
  /** Pasivo + PoC no destructivos (lectura mínima + canaries inertes). */
  | "active"
  /** Pentest profundo: CVEs, enumeración ampliada, muestreo, cadena de ataque. */
  | "deep";

export interface Finding {
  /** id versionado, p.ej. "exposed_api_keys.v1" */
  id: string;
  /** id del check sin versión, p.ej. "exposed_api_keys" */
  checkId: string;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  /** Detectado (pasivo) o confirmado con PoC (activo). */
  confidence: Confidence;
  /** Descripción corta del hallazgo */
  summary: string;
  /** Líneas de evidencia (ya censuradas) */
  evidence: string[];
  /**
   * Resultado del PoC no destructivo si se ejecutó (censurado), o null.
   * Ej: "GET /api/users → 200, devolvió 1 registro con campo `email`."
   */
  poc: string | null;
  /** Cómo solucionarlo, en español */
  remediation: string;
  /** Prompt listo para pegar en una IA y arreglarlo */
  prompt: string;
  /** Referencias (OWASP, CWE, docs) */
  references: string[];
  /** Pasos narrados de cómo un atacante encadenaría la vulnerabilidad. */
  attackChain: string[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AuditReport {
  id: string;
  url: string;
  finalUrl: string;
  /** Profundidad con la que se ejecutó la auditoría. */
  mode: AuditMode;
  /** ISO-8601 */
  createdAt: string;
  durationMs: number;
  /** 0-100 */
  score: number;
  /** A | B | C | D | F */
  grade: string;
  counts: SeverityCounts;
  findings: Finding[];
  checksRun: number;
}

export interface AuditSummary {
  id: string;
  url: string;
  createdAt: string;
  score: number;
  grade: string;
  counts: SeverityCounts;
}

export interface ProgressEvent {
  auditId: string;
  done: number;
  total: number;
  /** título del check en curso */
  current: string;
}
