use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use tauri::{AppHandle, Emitter};
use url::Url;
use uuid::Uuid;

use super::checks::registry;
use super::context::{build_client, AuditContext};
use super::ruleset::Ruleset;
use super::score::{counts_from, grade_from, score_from_findings};
use super::types::{AuditMode, AuditReport, Finding, ProgressEvent, Severity};

const PROGRESS_EVENT: &str = "audit://progress";

pub async fn run_audit(
    app: &AppHandle,
    raw_url: &str,
    mode: AuditMode,
    rules: Arc<Ruleset>,
) -> Result<AuditReport, String> {
    let target = normalize_url(raw_url)?;
    let started = Instant::now();
    let audit_id = Uuid::new_v4().to_string();

    let checks = registry();
    let total = checks.len() as u32;

    emit(app, &audit_id, 0, total, "Descargando la página…");

    let client =
        build_client().map_err(|e| format!("No se pudo crear el cliente HTTP: {e}"))?;
    let ctx = AuditContext::fetch(client, target.clone(), mode, rules).await?;

    let mut findings: Vec<Finding> = Vec::new();
    for (i, def) in checks.iter().enumerate() {
        emit(app, &audit_id, i as u32, total, def.name);
        let mut res = (def.run)(&ctx).await;
        findings.append(&mut res);
    }
    emit(app, &audit_id, total, total, "Generando reporte…");

    let counts = counts_from(&findings);
    let score = score_from_findings(&findings);
    let grade = grade_from(score);

    findings.sort_by_key(|f| severity_rank(f.severity));

    Ok(AuditReport {
        id: audit_id,
        url: target.to_string(),
        final_url: ctx.page.final_url.to_string(),
        mode,
        created_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        score,
        grade,
        counts,
        findings,
        checks_run: total,
    })
}

fn emit(app: &AppHandle, audit_id: &str, done: u32, total: u32, current: &str) {
    let _ = app.emit(
        PROGRESS_EVENT,
        ProgressEvent {
            audit_id: audit_id.to_string(),
            done,
            total,
            current: current.to_string(),
        },
    );
}

fn normalize_url(raw: &str) -> Result<Url, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("Ingresa una URL para auditar.".into());
    }
    let with_scheme = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    };
    let u = Url::parse(&with_scheme).map_err(|_| "URL inválida.".to_string())?;
    match u.scheme() {
        "http" | "https" => {}
        _ => return Err("Solo se admiten URLs http/https.".into()),
    }
    if u.host_str().is_none() {
        return Err("La URL no tiene un host válido.".into());
    }
    Ok(u)
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Clean => 5,
    }
}
