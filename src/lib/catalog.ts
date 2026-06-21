import { invoke } from "@tauri-apps/api/core";

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

/** Abre el diálogo nativo y guarda el PDF. Devuelve la ruta o null si se cancela. */
export function saveReportPdf(
  bytes: Uint8Array,
  filename: string,
): Promise<string | null> {
  return invoke<string | null>("save_report_pdf", {
    bytes: Array.from(bytes),
    filename,
  });
}
