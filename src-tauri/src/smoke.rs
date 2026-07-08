//! Tests de humo del motor (hacen red real). Ejecutar con:
//!   cargo test smoke -- --ignored --nocapture

use std::sync::Arc;

use crate::engine::checks::registry;
use crate::engine::context::{build_client, AuditContext};
use crate::engine::ruleset::{base_ruleset, parse_gitleaks, parse_kev, CISA_KEV_URL, GITLEAKS_URL};
use crate::engine::score::{grade_from, score_from_findings};
use crate::engine::types::AuditMode;
use url::Url;

#[tokio::test]
#[ignore]
async fn audit_real_site_deep() {
    let client = build_client().expect("client");
    let target = Url::parse("https://example.com").unwrap();
    let ctx = AuditContext::fetch(client, target, AuditMode::Deep, Arc::new(base_ruleset()))
        .await
        .expect("fetch");

    let mut all = Vec::new();
    for def in registry() {
        let res = (def.run)(&ctx).await;
        all.extend(res);
    }

    let score = score_from_findings(&all);
    let grade = grade_from(score);
    println!("Score {score}/100 ({grade}) · {} findings", all.len());
    assert!(!all.is_empty(), "el motor no devolvió ningún finding");
}

/// Valida que la generación de PDF produce un PDF válido (sin red).
#[test]
fn pdf_generation() {
    use crate::engine::types::{
        AuditMode, AuditReport, Finding, Severity, SeverityCounts,
    };
    let f = Finding::new("api_unauth", 1, "Endpoint accesible sin autenticación", "API", Severity::High)
        .summary("Devuelve datos JSON sin token. Expone posible PII: email.")
        .add_evidence("GET /api/users → 200, 4213 bytes de JSON")
        .poc("GET /api/users sin cabecera Authorization devuelve datos.")
        .attack_chain(&["Llamo al endpoint sin token.", "Recibo datos.", "Itero IDs y exfiltro."])
        .remediation("Exige autenticación en el servidor para todo endpoint que devuelva datos.")
        .refs(&["OWASP API1:2023", "CWE-306"]);
    let report = AuditReport {
        id: "test".into(),
        url: "https://api.example.com".into(),
        final_url: "https://api.example.com".into(),
        mode: AuditMode::Deep,
        created_at: "2026-07-08T15:00:00Z".into(),
        duration_ms: 1234,
        score: 45,
        grade: "D".into(),
        counts: SeverityCounts { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        findings: vec![f],
        checks_run: 18,
    };
    let bytes = crate::engine::pdf::generate(&report).expect("pdf generation");
    println!("PDF generado: {} bytes", bytes.len());
    std::fs::write("/tmp/vibeauditt-test.pdf", &bytes).ok();
    assert!(bytes.starts_with(b"%PDF"), "no es un PDF válido");
    assert!(bytes.len() > 1000, "PDF demasiado pequeño");
}

/// Valida que el escaneo de código local recorre archivos sin panic.
#[tokio::test]
#[ignore]
async fn code_scan_smoke() {
    let report = crate::engine::code_scan::scan_code("../src")
        .await
        .expect("code scan");
    println!(
        "Code scan → {} archivos · {} findings · score {}/100",
        report.checks_run,
        report.findings.len(),
        report.score
    );
    for f in &report.findings {
        println!("  {:?}  {}", f.severity, f.title);
    }
    assert!(report.checks_run > 0, "no se escaneó ningún archivo");
}

/// Valida que el escaneo de API descubre endpoints y produce hallazgos.
#[tokio::test]
#[ignore]
async fn api_scan_smoke() {
    let report = crate::engine::api_scan::scan_api(
        "https://jsonplaceholder.typicode.com",
        AuditMode::Deep,
    )
    .await
    .expect("api scan");
    println!(
        "API scan → {} findings · score {}/100",
        report.findings.len(),
        report.score
    );
    for f in &report.findings {
        println!("  {:?}  {}", f.severity, f.title);
    }
    assert!(!report.findings.is_empty(), "el escaneo de API no devolvió nada");
}

/// Valida que la integración con OSV.dev devuelve CVEs reales.
#[tokio::test]
#[ignore]
async fn osv_known_vuln() {
    let client = build_client().expect("client");
    let body = serde_json::json!({
        "version": "0.21.1",
        "package": { "name": "axios", "ecosystem": "npm" }
    })
    .to_string();

    let resp = client
        .post("https://api.osv.dev/v1/query")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("osv request");
    let v: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    let vulns = v.get("vulns").and_then(|x| x.as_array()).cloned().unwrap_or_default();
    println!("axios 0.21.1 → {} vulnerabilidad(es) en OSV", vulns.len());
    assert!(!vulns.is_empty(), "OSV debería reportar vulns para axios 0.21.1");
}

/// Valida que las fuentes públicas del catálogo (gitleaks + CISA KEV) están vivas.
#[tokio::test]
#[ignore]
async fn catalog_sources() {
    let client = build_client().expect("client");

    let gl = client
        .get(GITLEAKS_URL)
        .send()
        .await
        .expect("gitleaks req")
        .text()
        .await
        .expect("gitleaks body");
    let rules = parse_gitleaks(&gl);
    println!("gitleaks → {} reglas compilables en Rust", rules.len());
    assert!(rules.len() > 40, "gitleaks debería aportar muchas reglas");

    let kev_txt = client
        .get(CISA_KEV_URL)
        .send()
        .await
        .expect("kev req")
        .text()
        .await
        .expect("kev body");
    let kev = parse_kev(&kev_txt);
    println!("CISA KEV → {} CVEs en explotación activa", kev.len());
    assert!(kev.len() > 500, "KEV debería tener cientos de CVEs");
}
