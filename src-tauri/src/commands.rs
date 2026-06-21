use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::db::Db;
use crate::engine::context::build_client;
use crate::engine::db_audit;
use crate::engine::ruleset::{
    base_ruleset, parse_gitleaks, parse_kev, CISA_KEV_URL, GITLEAKS_URL,
};
use crate::engine::runner;
use crate::engine::types::{AuditMode, AuditReport, AuditSummary};

const LOCK_ERR: &str = "No se pudo acceder al almacén local.";

#[tauri::command]
pub async fn run_audit(
    app: AppHandle,
    db: State<'_, Mutex<Db>>,
    url: String,
    mode: AuditMode,
    consent: bool,
) -> Result<AuditReport, String> {
    if !consent {
        return Err("Debes confirmar que tienes autorización para auditar esta URL.".to_string());
    }

    // Cargamos el catálogo actual (o el base si nunca se actualizó).
    let rules = {
        let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
        Arc::new(db.load_catalog().unwrap_or_else(base_ruleset))
    };

    let report = runner::run_audit(&app, &url, mode, rules).await?;

    {
        let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
        db.save(&report)?;
    }

    Ok(report)
}

#[tauri::command]
pub fn list_audits(db: State<'_, Mutex<Db>>) -> Result<Vec<AuditSummary>, String> {
    let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
    db.list()
}

#[tauri::command]
pub fn get_audit(db: State<'_, Mutex<Db>>, id: String) -> Result<AuditReport, String> {
    let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
    db.get(&id)
}

#[tauri::command]
pub fn delete_audit(db: State<'_, Mutex<Db>>, id: String) -> Result<(), String> {
    let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
    db.delete(&id)
}

/// Audita una base de datos PostgreSQL/Supabase conectándose con credenciales.
/// La cadena de conexión NO se guarda: solo se usa para esta auditoría.
#[tauri::command]
pub async fn audit_database(
    db: State<'_, Mutex<Db>>,
    connection: String,
    consent: bool,
) -> Result<AuditReport, String> {
    if !consent {
        return Err(
            "Debes confirmar que tienes autorización para auditar esta base de datos.".to_string(),
        );
    }
    let report = db_audit::audit_database(&connection).await?;
    {
        let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
        db.save(&report)?;
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Catálogo de detección (reglas actualizables)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogInfo {
    pub total_secret_rules: usize,
    pub total_kev: usize,
    pub version: String,
    pub updated_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogUpdate {
    pub added_secret_rules: usize,
    pub added_kev: usize,
    pub total_secret_rules: usize,
    pub total_kev: usize,
    pub version: String,
    pub updated_at: String,
}

#[tauri::command]
pub fn get_catalog_info(db: State<'_, Mutex<Db>>) -> Result<CatalogInfo, String> {
    let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
    let rules = db.load_catalog().unwrap_or_else(base_ruleset);
    Ok(CatalogInfo {
        total_secret_rules: rules.secret_rules.len(),
        total_kev: rules.kev_cves.len(),
        version: rules.version,
        updated_at: db.catalog_updated_at(),
    })
}

/// Descarga reglas frescas de fuentes públicas (gitleaks + CISA KEV), las
/// fusiona con el catálogo local y devuelve cuántas se añadieron.
#[tauri::command]
pub async fn update_catalog(db: State<'_, Mutex<Db>>) -> Result<CatalogUpdate, String> {
    let mut rules = {
        let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
        db.load_catalog().unwrap_or_else(base_ruleset)
    };

    let client = build_client().map_err(|e| format!("No se pudo crear el cliente HTTP: {e}"))?;

    let mut added_secret_rules = 0;
    if let Ok(resp) = client.get(GITLEAKS_URL).send().await {
        if let Ok(text) = resp.text().await {
            added_secret_rules = rules.merge_secret_rules(parse_gitleaks(&text));
        }
    }

    let mut added_kev = 0;
    if let Ok(resp) = client.get(CISA_KEV_URL).send().await {
        if let Ok(text) = resp.text().await {
            added_kev = rules.merge_kev(parse_kev(&text));
        }
    }

    let now = chrono::Utc::now();
    let updated_at = now.to_rfc3339();
    rules.version = now.format("%Y.%m.%d").to_string();

    let total_secret_rules = rules.secret_rules.len();
    let total_kev = rules.kev_cves.len();
    let version = rules.version.clone();

    {
        let db = db.lock().map_err(|_| LOCK_ERR.to_string())?;
        db.save_catalog(&rules, &updated_at)?;
    }

    Ok(CatalogUpdate {
        added_secret_rules,
        added_kev,
        total_secret_rules,
        total_kev,
        version,
        updated_at,
    })
}

// ---------------------------------------------------------------------------
// Exportar PDF (el frontend genera los bytes; aquí abrimos el diálogo y guardamos)
// ---------------------------------------------------------------------------

/// Abre un diálogo nativo "Guardar como" y escribe los bytes del PDF.
/// Devuelve la ruta guardada o None si el usuario cancela.
#[tauri::command]
pub async fn save_report_pdf(
    app: AppHandle,
    bytes: Vec<u8>,
    filename: String,
) -> Result<Option<String>, String> {
    let file_path = app
        .dialog()
        .file()
        .add_filter("PDF", &["pdf"])
        .set_file_name(filename)
        .blocking_save_file();

    match file_path {
        Some(fp) => {
            let path = fp.into_path().map_err(|e| format!("Ruta inválida: {e}"))?;
            std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
            Ok(Some(path.to_string_lossy().to_string()))
        }
        None => Ok(None),
    }
}
