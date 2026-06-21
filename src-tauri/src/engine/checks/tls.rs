use std::time::Duration;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1) ¿HTTPS en absoluto?
    if ctx.page.final_url.scheme() != "https" {
        return vec![Finding::new(
            "no_https",
            1,
            "El sitio no usa HTTPS",
            cat::TLS,
            Severity::Critical,
        )
        .summary(
            "El tráfico viaja sin cifrar: cualquiera en la red puede leer o modificar los datos, \
             incluidas credenciales.",
        )
        .add_evidence(format!("URL final: {}", ctx.page.final_url))
        .remediation(
            "Sirve todo el sitio por HTTPS con un certificado válido (Let's Encrypt / Cloudflare) \
             y fuerza la redirección de HTTP a HTTPS.",
        )
        .prompt(
            "Mi sitio se sirve por HTTP sin cifrar. Explícame cómo activar HTTPS con un \
             certificado válido y forzar la redirección desde HTTP en mi hosting.",
        )
        .refs(&["CWE-319: Cleartext Transmission of Sensitive Information"])];
    }

    // 2) ¿La versión HTTP redirige a HTTPS?
    let host = ctx.host();
    if !host.is_empty() {
        if let Ok(nc) = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(8))
            .build()
        {
            let http_url = format!("http://{host}/");
            if let Ok(r) = nc.get(&http_url).send().await {
                let st = r.status().as_u16();
                if (200..300).contains(&st) {
                    findings.push(
                        Finding::new(
                            "no_https_redirect",
                            1,
                            "HTTP no redirige a HTTPS",
                            cat::TLS,
                            Severity::Medium,
                        )
                        .summary(
                            "La versión HTTP responde 200 sin redirigir a HTTPS, permitiendo \
                             navegación insegura.",
                        )
                        .add_evidence(format!("GET {http_url} → {st} (sin redirección a https)"))
                        .poc(format!("GET {http_url} responde {st} en texto plano, sin 301 a HTTPS."))
                        .remediation(
                            "Configura una redirección 301 de HTTP a HTTPS para todo el dominio.",
                        )
                        .prompt(
                            "Configura la redirección 301 permanente de HTTP a HTTPS para todo mi \
                             dominio en el hosting.",
                        ),
                    );
                }
            }
        }
    }

    // 3) Contenido mixto (recursos http en página https).
    let html = &ctx.page.html;
    let mixed = html.matches("src=\"http://").count() + html.matches("href=\"http://").count();
    if mixed > 0 {
        findings.push(
            Finding::new(
                "mixed_content",
                1,
                "Contenido mixto (recursos por HTTP)",
                cat::TLS,
                Severity::Low,
            )
            .summary(
                "La página HTTPS referencia recursos por http://. Los navegadores los bloquean o \
                 degradan la seguridad de la página.",
            )
            .add_evidence(format!("{mixed} referencia(s) a http:// en el HTML"))
            .remediation("Carga todos los recursos por https:// o con rutas relativas.")
            .prompt(
                "Tengo contenido mixto (recursos http:// en una página https). Ayúdame a \
                 localizarlos y migrarlos todos a https.",
            ),
        );
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass("tls", 1, "HTTPS correcto", cat::TLS)
                .summary("El sitio se sirve por HTTPS y el tráfico inseguro se redirige."),
        );
    }

    findings
}
