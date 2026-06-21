use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let is_https = ctx.page.final_url.scheme() == "https";

    let csp = ctx.header("content-security-policy");
    match &csp {
        None => findings.push(
            Finding::new(
                "missing_csp",
                1,
                "Content-Security-Policy ausente",
                cat::HEADERS,
                Severity::Medium,
            )
            .summary("No se envía CSP: el navegador no tiene defensa contra inyección de scripts.")
            .remediation(
                "Añade una cabecera Content-Security-Policy. Empieza por una política \
                 restrictiva como default-src 'self' y ve permitiendo orígenes concretos.",
            )
            .prompt(
                "Mi app no envía la cabecera Content-Security-Policy. Genera una CSP \
                 razonable para una SPA (React/Vite) servida en mi dominio, explicando cada \
                 directiva, y dime cómo añadirla en mi hosting.",
            )
            .refs(&["OWASP Secure Headers", "CWE-693: Protection Mechanism Failure"]),
        ),
        Some(v) => {
            let lower = v.to_lowercase();
            if lower.contains("unsafe-inline") || lower.contains("unsafe-eval") {
                findings.push(
                    Finding::new(
                        "weak_csp",
                        1,
                        "CSP débil (unsafe-inline / unsafe-eval)",
                        cat::HEADERS,
                        Severity::Low,
                    )
                    .summary("Hay CSP, pero permite scripts inline o eval, lo que reduce su valor.")
                    .add_evidence(crate::engine::util::snippet(v, 160))
                    .remediation(
                        "Elimina 'unsafe-inline' y 'unsafe-eval'. Usa nonces o hashes para los \
                         scripts inline imprescindibles.",
                    )
                    .prompt(
                        "Mi CSP usa unsafe-inline/unsafe-eval. Ayúdame a migrar a nonces/hashes \
                         para eliminar esas directivas sin romper la app.",
                    ),
                );
            }
        }
    }

    // HSTS (solo relevante en https)
    if is_https && ctx.header("strict-transport-security").is_none() {
        findings.push(
            Finding::new(
                "missing_hsts",
                1,
                "Strict-Transport-Security ausente",
                cat::HEADERS,
                Severity::Medium,
            )
            .summary("Sin HSTS, un atacante puede forzar una conexión HTTP y hacer downgrade.")
            .remediation(
                "Añade Strict-Transport-Security: max-age=31536000; includeSubDomains. \
                 Considera el preload list una vez verificado.",
            )
            .prompt(
                "Añade la cabecera HSTS (Strict-Transport-Security) correctamente a mi sitio \
                 servido por HTTPS y explícame el riesgo de includeSubDomains y preload.",
            )
            .refs(&["OWASP Secure Headers — HSTS"]),
        );
    }

    // Clickjacking: X-Frame-Options o CSP frame-ancestors
    let has_frame_ancestors = csp
        .as_ref()
        .map(|v| v.to_lowercase().contains("frame-ancestors"))
        .unwrap_or(false);
    if ctx.header("x-frame-options").is_none() && !has_frame_ancestors {
        findings.push(
            Finding::new(
                "missing_xfo",
                1,
                "Protección anti-clickjacking ausente",
                cat::HEADERS,
                Severity::Medium,
            )
            .summary("Falta X-Frame-Options y CSP frame-ancestors: la página puede embeberse en un iframe.")
            .remediation(
                "Añade X-Frame-Options: DENY (o SAMEORIGIN) o, mejor, CSP \
                 frame-ancestors 'none'.",
            )
            .prompt(
                "Protege mi app contra clickjacking añadiendo X-Frame-Options y/o la directiva \
                 CSP frame-ancestors. Dime los valores recomendados.",
            )
            .refs(&["CWE-1021: Improper Restriction of Rendered UI Layers"]),
        );
    }

    // X-Content-Type-Options
    let xcto = ctx
        .header("x-content-type-options")
        .map(|v| v.to_lowercase().contains("nosniff"))
        .unwrap_or(false);
    if !xcto {
        findings.push(
            Finding::new(
                "missing_xcto",
                1,
                "X-Content-Type-Options ausente",
                cat::HEADERS,
                Severity::Low,
            )
            .summary("Sin 'nosniff', el navegador puede interpretar tipos MIME de forma insegura.")
            .remediation("Añade X-Content-Type-Options: nosniff.")
            .prompt("Añade la cabecera X-Content-Type-Options: nosniff a todas las respuestas."),
        );
    }

    // Referrer-Policy
    if ctx.header("referrer-policy").is_none() {
        findings.push(
            Finding::new(
                "missing_referrer_policy",
                1,
                "Referrer-Policy ausente",
                cat::HEADERS,
                Severity::Low,
            )
            .summary("Sin Referrer-Policy se pueden filtrar URLs internas a terceros.")
            .remediation("Añade Referrer-Policy: strict-origin-when-cross-origin.")
            .prompt("Añade una Referrer-Policy adecuada (strict-origin-when-cross-origin) a mi app."),
        );
    }

    // Information disclosure por Server / X-Powered-By
    let mut disclosed = Vec::new();
    if let Some(s) = ctx.header("x-powered-by") {
        disclosed.push(format!("X-Powered-By: {s}"));
    }
    if let Some(s) = ctx.header("server") {
        if s.chars().any(|c| c.is_ascii_digit()) {
            disclosed.push(format!("Server: {s}"));
        }
    }
    if !disclosed.is_empty() {
        findings.push(
            Finding::new(
                "info_disclosure_headers",
                1,
                "Cabeceras que revelan tecnología",
                cat::HEADERS,
                Severity::Info,
            )
            .summary("Las cabeceras de respuesta revelan el stack/versión, útil para un atacante.")
            .evidence(disclosed)
            .remediation("Oculta o normaliza las cabeceras Server y X-Powered-By.")
            .prompt("Elimina las cabeceras X-Powered-By y reduce el detalle de la cabecera Server."),
        );
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass("security_headers", 1, "Cabeceras de seguridad correctas", cat::HEADERS)
                .summary("Las cabeceras de seguridad principales están presentes."),
        );
    }

    findings
}
