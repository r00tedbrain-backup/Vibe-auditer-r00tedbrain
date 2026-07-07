import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AuditMode,
  AuditReport,
  AuditSummary,
  ProgressEvent,
} from "./types";

/** Lanza una auditoría completa contra una URL. Resuelve con el reporte. */
export function runAudit(
  url: string,
  mode: AuditMode,
  consent: boolean,
): Promise<AuditReport> {
  return invoke<AuditReport>("run_audit", { url, mode, consent });
}

/**
 * Audita una base de datos PostgreSQL/Supabase con credenciales.
 * La cadena de conexión NO se guarda; solo se usa para esta auditoría.
 */
export function auditDatabase(
  connection: string,
  consent: boolean,
): Promise<AuditReport> {
  return invoke<AuditReport>("audit_database", { connection, consent });
}

/** Escanea una API (URL base) buscando vulnerabilidades, sin auth y no destructivo. */
export function scanApi(base: string, consent: boolean): Promise<AuditReport> {
  return invoke<AuditReport>("scan_api", { base, consent });
}

/** Histórico de auditorías guardadas (resumen, sin findings). */
export function listAudits(): Promise<AuditSummary[]> {
  return invoke<AuditSummary[]>("list_audits");
}

/** Reporte completo por id. */
export function getAudit(id: string): Promise<AuditReport> {
  return invoke<AuditReport>("get_audit", { id });
}

/** Elimina una auditoría del histórico. */
export function deleteAudit(id: string): Promise<void> {
  return invoke("delete_audit", { id });
}

/** Suscripción al progreso de la auditoría en curso. */
export function onAuditProgress(
  cb: (p: ProgressEvent) => void,
): Promise<UnlistenFn> {
  return listen<ProgressEvent>("audit://progress", (e) => cb(e.payload));
}
