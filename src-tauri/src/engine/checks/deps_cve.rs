use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

// Extrae pares (nombre, versión) de banners de licencia: `/*! name vX.Y.Z`
// y `@license name vX.Y.Z`. Precisión alta, cobertura parcial (solo libs con banner).
static RE_BANNER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:/\*!|@license|@preserve)\s*([A-Za-z][\w.\-]{1,30})[^\n]{0,40}?v?(\d+\.\d+\.\d+)")
        .unwrap()
});

const MAX_LIBS: usize = 12;

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    if !ctx.mode.is_deep() {
        return Vec::new();
    }

    let source = ctx.all_source();

    // Candidatos únicos nombre -> versión.
    let mut candidates: HashMap<String, String> = HashMap::new();
    for cap in RE_BANNER.captures_iter(&source) {
        let name = cap[1].to_lowercase();
        let version = cap[2].to_string();
        // Filtra ruido obvio.
        if name.len() < 2 || name == "v" {
            continue;
        }
        candidates.entry(name).or_insert(version);
        if candidates.len() >= MAX_LIBS {
            break;
        }
    }

    if candidates.is_empty() {
        return vec![Finding::pass(
            "deps_cve",
            1,
            "Sin dependencias con versión identificable",
            cat::CLIENT,
        )
        .summary(
            "No se pudo extraer la versión de librerías desde los banners del bundle (suele \
             ocurrir con builds totalmente minificados).",
        )];
    }

    let mut findings = Vec::new();
    for (name, version) in candidates {
        let vulns = osv_query(ctx, &name, &version).await;
        if vulns.is_empty() {
            continue;
        }

        let mut worst = Severity::Low;
        let mut ids: Vec<String> = Vec::new();
        let mut summaries: Vec<String> = Vec::new();
        for v in vulns.iter().take(6) {
            if let Some(sev) = severity_of(v) {
                worst = max_sev(worst, sev);
            }
            let id = best_id(v);
            if !id.is_empty() {
                ids.push(id);
            }
            if let Some(s) = v.get("summary").and_then(|x| x.as_str()) {
                summaries.push(crate::engine::util::snippet(s, 110));
            }
        }
        if ids.is_empty() {
            continue;
        }

        let mut evidence = vec![format!("{name}@{version} → {} vulnerabilidad(es) conocida(s)", ids.len())];
        evidence.extend(ids.iter().cloned());
        evidence.extend(summaries.into_iter().take(3));

        // ¿Algún CVE está en explotación activa (CISA KEV)?
        let in_kev: Vec<String> = ids
            .iter()
            .filter(|id| ctx.rules.kev_cves.contains(*id))
            .cloned()
            .collect();
        let severity = if in_kev.is_empty() { worst } else { Severity::Critical };
        let kev_note = if in_kev.is_empty() {
            String::new()
        } else {
            evidence.push(format!("En explotación activa (CISA KEV): {}", in_kev.join(", ")));
            " Está en explotación activa según CISA KEV.".to_string()
        };

        findings.push(
            Finding::new(
                "deps_cve",
                1,
                &format!("Dependencia vulnerable: {name}@{version}"),
                cat::CLIENT,
                severity,
            )
            .summary(format!(
                "La librería {name} {version} tiene vulnerabilidades conocidas registradas en OSV.{kev_note}"
            ))
            .evidence(evidence)
            .poc(format!(
                "Fingerprint del bundle → {name}@{version}; OSV reporta {}: {}.",
                ids.len(),
                ids.first().cloned().unwrap_or_default()
            ))
            .attack_chain(&[
                "Identifico la versión exacta de la librería por su banner en el bundle.",
                "Busco exploits públicos para esa versión (OSV / GitHub advisories / exploit-db).",
                "Adapto el PoC del CVE a tu aplicación para comprometerla.",
            ])
            .remediation(format!(
                "Actualiza {name} a la última versión parcheada y revisa el changelog de seguridad. \
                 Automatiza la detección con `npm audit` o Dependabot."
            ))
            .prompt(format!(
                "Mi app usa {name}@{version}, que tiene CVEs conocidos ({}). Dime a qué versión \
                 segura actualizar, los breaking changes a tener en cuenta y cómo verificarlo.",
                ids.first().cloned().unwrap_or_default()
            ))
            .refs(&["https://osv.dev", "OWASP A06:2021 — Vulnerable and Outdated Components"]),
        );
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass("deps_cve", 1, "Dependencias sin CVEs conocidos", cat::CLIENT).summary(
                "Las librerías identificadas por banner no tienen vulnerabilidades conocidas en OSV.",
            ),
        );
    }

    findings
}

async fn osv_query(ctx: &AuditContext, name: &str, version: &str) -> Vec<Value> {
    let body = json!({
        "version": version,
        "package": { "name": name, "ecosystem": "npm" }
    })
    .to_string();

    let Ok(resp) = ctx
        .client
        .post("https://api.osv.dev/v1/query")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(text) = resp.text().await else {
        return Vec::new();
    };
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("vulns").and_then(|x| x.as_array()).cloned())
        .unwrap_or_default()
}

fn best_id(v: &Value) -> String {
    // Prefiere un CVE entre los alias; si no, el id de OSV.
    if let Some(aliases) = v.get("aliases").and_then(|x| x.as_array()) {
        for a in aliases {
            if let Some(s) = a.as_str() {
                if s.starts_with("CVE-") {
                    return s.to_string();
                }
            }
        }
    }
    v.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn severity_of(v: &Value) -> Option<Severity> {
    let label = v
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    match label.to_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MODERATE" | "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

fn max_sev(a: Severity, b: Severity) -> Severity {
    let rank = |s: Severity| match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Clean => 0,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}
