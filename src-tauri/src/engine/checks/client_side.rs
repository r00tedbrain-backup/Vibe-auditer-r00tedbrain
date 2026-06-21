use url::Url;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

const MARKER: &str = "sourceMappingURL=";

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1) Source maps referenciados en los bundles.
    let mut map_urls: Vec<String> = Vec::new();
    for b in &ctx.page.bundles {
        if let Some(idx) = b.body.rfind(MARKER) {
            let tail = &b.body[idx + MARKER.len()..];
            let map_ref = tail
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches(|c| c == '*' || c == '/')
                .trim();
            if map_ref.is_empty() || map_ref.starts_with("data:") {
                continue;
            }
            if let Ok(abs) = Url::parse(&b.url).and_then(|u| u.join(map_ref)) {
                let s = abs.to_string();
                if !map_urls.contains(&s) {
                    map_urls.push(s);
                }
            }
        }
    }

    // Confirmamos si el .map es accesible públicamente (GET, recurso estático).
    let mut accessible: Vec<String> = Vec::new();
    for m in map_urls.iter().take(3) {
        if let Ok(resp) = ctx.client.get(m).send().await {
            if resp.status().is_success() {
                accessible.push(m.clone());
            }
        }
    }

    if !accessible.is_empty() {
        findings.push(
            Finding::new(
                "exposed_sourcemaps",
                1,
                "Source maps expuestos en producción",
                cat::CLIENT,
                Severity::Low,
            )
            .summary(
                "Hay archivos .map accesibles: revelan el código fuente original sin minificar, \
                 incluyendo comentarios y estructura interna.",
            )
            .evidence(accessible.clone())
            .poc(format!(
                "GET {} → 200. El source map descarga el código fuente original.",
                accessible[0]
            ))
            .remediation(
                "Desactiva la generación de source maps en producción (build.sourcemap=false \
                 en Vite) o impide servir los .map desde tu hosting.",
            )
            .prompt(
                "Tengo source maps (.map) accesibles en producción. Desactívalos en mi build \
                 de Vite/producción y dime cómo bloquear su acceso en el hosting.",
            )
            .refs(&["CWE-540: Inclusion of Sensitive Information in Source Code"]),
        );
    }

    // 2) Tamaño total de los bundles (señal de performance, informativo).
    let total: usize = ctx.page.bundles.iter().map(|b| b.body.len()).sum();
    if total > 1_500_000 {
        findings.push(
            Finding::new(
                "large_bundle",
                1,
                "Bundle JavaScript muy grande",
                cat::CLIENT,
                Severity::Info,
            )
            .summary(format!(
                "Los bundles analizados suman ~{} KB. Afecta al tiempo de carga.",
                total / 1024
            ))
            .remediation(
                "Aplica code-splitting, carga diferida (lazy) de rutas y revisa dependencias \
                 pesadas (moment, lodash completo, etc.).",
            )
            .prompt(
                "Mi bundle JS es muy grande. Propón code-splitting y lazy loading para mi app \
                 y detecta dependencias pesadas que pueda sustituir.",
            ),
        );
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass("client_quality", 1, "Bundle sin fugas evidentes", cat::CLIENT)
                .summary("No se detectaron source maps expuestos ni bundles desproporcionados."),
        );
    }

    findings
}
