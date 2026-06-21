use std::sync::LazyLock;

use regex::Regex;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};
use crate::engine::util::looks_like_html;

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=").unwrap());

fn is_env(b: &str) -> bool {
    !looks_like_html(b) && ENV_RE.is_match(b)
}
fn is_php(b: &str) -> bool {
    b.contains("<?php") || b.contains("DB_PASSWORD")
}
fn is_sql(b: &str) -> bool {
    let u = b.to_uppercase();
    u.contains("INSERT INTO") || u.contains("CREATE TABLE")
}
fn is_json_cfg(b: &str) -> bool {
    !looks_like_html(b) && b.trim_start().starts_with('{')
}
fn is_npmrc(b: &str) -> bool {
    !looks_like_html(b) && (b.contains("_authToken") || b.contains("registry="))
}
fn is_compose(b: &str) -> bool {
    !looks_like_html(b) && b.contains("services:")
}
fn is_ds_store(b: &str) -> bool {
    b.as_bytes().windows(4).take(64).any(|w| w == b"Bud1")
}

struct Probe {
    path: &'static str,
    label: &'static str,
    severity: Severity,
    validate: fn(&str) -> bool,
}

const PROBES: &[Probe] = &[
    Probe { path: "/.env", label: "Archivo .env", severity: Severity::Critical, validate: is_env },
    Probe { path: "/.env.local", label: "Archivo .env.local", severity: Severity::Critical, validate: is_env },
    Probe { path: "/.env.production", label: "Archivo .env.production", severity: Severity::Critical, validate: is_env },
    Probe { path: "/.npmrc", label: "Archivo .npmrc (tokens)", severity: Severity::High, validate: is_npmrc },
    Probe { path: "/wp-config.php", label: "wp-config.php", severity: Severity::Critical, validate: is_php },
    Probe { path: "/config.json", label: "config.json", severity: Severity::Medium, validate: is_json_cfg },
    Probe { path: "/backup.sql", label: "Backup SQL (backup.sql)", severity: Severity::Critical, validate: is_sql },
    Probe { path: "/dump.sql", label: "Backup SQL (dump.sql)", severity: Severity::Critical, validate: is_sql },
    Probe { path: "/database.sql", label: "Backup SQL (database.sql)", severity: Severity::Critical, validate: is_sql },
    Probe { path: "/docker-compose.yml", label: "docker-compose.yml", severity: Severity::Medium, validate: is_compose },
    Probe { path: "/.DS_Store", label: "Archivo .DS_Store", severity: Severity::Low, validate: is_ds_store },
];

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    for p in PROBES {
        let Some(resp) = ctx.get_path(p.path).await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        if !(p.validate)(&body) {
            continue;
        }
        // Evidencia genérica: NO volcamos el contenido (puede contener secretos/PII).
        findings.push(
            Finding::new("exposed_file", 1, p.label, cat::CONFIG, p.severity)
                .summary(format!(
                    "El archivo {} es accesible públicamente y contiene datos sensibles.",
                    p.path
                ))
                .add_evidence(format!("GET {} → 200 ({} bytes, contenido válido)", p.path, body.len()))
                .poc(format!(
                    "GET {} devuelve el archivo real (no el index de la SPA).",
                    p.path
                ))
                .attack_chain(&[
                    "Pruebo rutas de archivos sensibles comunes (.env, backups, configs).",
                    "Descargo el archivo expuesto directamente con un simple GET.",
                    "Extraigo credenciales y configuración para acceder a tus sistemas.",
                ])
                .remediation(
                    "Impide servir este archivo desde tu hosting/CDN y elimínalo del directorio \
                     público. Si contenía secretos, rótalos.",
                )
                .prompt(format!(
                    "El archivo {} está accesible públicamente en mi web. Dime cómo bloquear su \
                     acceso en mi hosting y, si tenía credenciales, cómo rotarlas.",
                    p.path
                ))
                .refs(&["CWE-538: File and Directory Information Exposure"]),
        );
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass("exposed_file", 1, "Sin archivos sensibles expuestos", cat::CONFIG)
                .summary("No se encontraron .env, backups ni configs accesibles en las rutas probadas."),
        );
    }

    findings
}

pub async fn git(ctx: &AuditContext) -> Vec<Finding> {
    if let Some(resp) = ctx.get_path("/.git/HEAD").await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.trim_start().starts_with("ref:") {
                return vec![Finding::new(
                    "exposed_git",
                    1,
                    "Directorio .git expuesto",
                    cat::CONFIG,
                    Severity::Critical,
                )
                .summary(
                    "El directorio .git es accesible: se puede reconstruir todo el código fuente \
                     y el historial completo del repositorio.",
                )
                .add_evidence(format!("GET /.git/HEAD → 200: {}", body.trim()))
                .poc(
                    "GET /.git/HEAD devuelve la rama actual; con herramientas como git-dumper se \
                     descarga el repositorio entero.",
                )
                .attack_chain(&[
                    "Detecto /.git/HEAD accesible públicamente.",
                    "Con git-dumper descargo todo el directorio .git.",
                    "Reconstruyo tu código fuente, historial y secretos commiteados.",
                    "Busco claves, lógica de negocio y vulnerabilidades en el código.",
                ])
                .remediation(
                    "Bloquea el acceso a /.git en tu servidor/CDN o no incluyas el .git en el \
                     despliegue.",
                )
                .prompt(
                    "Mi directorio /.git está expuesto en producción. Indícame cómo bloquear el \
                     acceso a /.git en mi hosting (Vercel/Netlify/Cloudflare/nginx) y cómo \
                     verificar que ya no es accesible.",
                )
                .refs(&["CWE-527: Exposure of Version-Control Repository to Web"])];
            }
        }
    }
    vec![Finding::pass("exposed_git", 1, "Directorio .git no accesible", cat::CONFIG)
        .summary("/.git/HEAD no responde con contenido de repositorio.")]
}
