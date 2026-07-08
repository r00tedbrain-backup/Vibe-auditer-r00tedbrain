import { invoke } from "@tauri-apps/api/core";
import type { AuditReport } from "./types";

export interface CatalogInfo {
  totalSecretRules: number;
  totalKev: number;
  version: string;
  updatedAt: string | null;
}

export interface CatalogUpdate {
  addedSecretRules: number;
  addedKev: number;
  totalSecretRules: number;
  totalKev: number;
  version: string;
  updatedAt: string;
}

export function getCatalogInfo(): Promise<CatalogInfo> {
  return invoke<CatalogInfo>("get_catalog_info");
}

/** Descarga reglas frescas (gitleaks + CISA KEV) y devuelve el diff. */
export function updateCatalog(): Promise<CatalogUpdate> {
  return invoke<CatalogUpdate>("update_catalog");
}

/**
 * Genera el PDF del reporte (en Rust) y abre el diálogo nativo de guardado.
 * Devuelve la ruta guardada o null si se cancela.
 */
export function saveReportPdf(report: AuditReport): Promise<string | null> {
  return invoke<string | null>("save_report_pdf", { report });
}
