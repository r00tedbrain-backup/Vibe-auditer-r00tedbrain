use std::time::Duration;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

const CANARY: &str = "vqa9z7marker";
const REDIRECT_TARGET: &str = "https://vibeauditt-redirect-probe.example/";

/// XSS reflejado: inyecta un marcador INERTE (no ejecutable) en un query param
/// y comprueba si vuelve sin escapar en el HTML. Nunca ejecuta scripts.
pub async fn reflected(ctx: &AuditContext) -> Vec<Finding> {
    if !ctx.mode.is_active() {
        return vec![Finding::pass(
            "reflected_xss",
            1,
            "XSS reflejado no probado (modo pasivo)",
            cat::INJECTION,
        )
        .summary("Activa el modo PoC para probar el reflejo de parámetros sin sanitizar.")];
    }

    // Marcador inerte: una etiqueta inventada que el navegador no ejecuta.
    let payload = format!("<vqa-svg>{CANARY}</vqa-svg>");
    let mut url = ctx.page.final_url.clone();
    url.query_pairs_mut().append_pair("vibeauditt_probe", &payload);

    let Ok(r) = ctx.client.get(url.clone()).send().await else {
        return vec![Finding::pass(
            "reflected_xss",
            1,
            "XSS reflejado no evaluable",
            cat::INJECTION,
        )
        .summary("No se pudo completar la prueba de reflejo.")];
    };
    if !r.status().is_success() {
        return vec![Finding::pass("reflected_xss", 1, "Sin reflejo detectado", cat::INJECTION)
            .summary("El parámetro de prueba no produjo una respuesta válida.")];
    }
    let body = r.text().await.unwrap_or_default();

    if body.contains(&payload) {
        vec![Finding::new(
            "reflected_xss",
            1,
            "Parámetro reflejado sin sanitizar",
            cat::INJECTION,
            Severity::High,
        )
        .summary(
            "Un parámetro de la URL se refleja en el HTML sin escapar: posible XSS reflejado.",
        )
        .add_evidence(format!("El marcador inerte «{payload}» volvió sin escapar en la respuesta."))
        .poc(
            "Se inyectó un marcador inerte <vqa-svg> en un query param y regresó sin escapar en \
             el HTML (no se ejecutó ningún script).",
        )
        .remediation(
            "Escapa toda entrada del usuario al renderizarla en HTML. Usa el escaping del \
             framework y una CSP estricta como defensa en profundidad.",
        )
        .prompt(
            "Un parámetro de mi URL se refleja en el HTML sin escapar (XSS reflejado). Muéstrame \
             cómo escapar esa salida en mi framework y añadir una CSP que lo mitigue.",
        )
        .refs(&["OWASP A03:2021 — Injection", "CWE-79: Cross-site Scripting"])]
    } else {
        vec![Finding::pass(
            "reflected_xss",
            1,
            "Sin reflejo sin sanitizar",
            cat::INJECTION,
        )
        .summary("El marcador de prueba no apareció sin escapar en la respuesta.")]
    }
}

/// Open redirect: prueba parámetros comunes con un destino externo y comprueba
/// si la app emite una redirección hacia ese dominio.
pub async fn open_redirect(ctx: &AuditContext) -> Vec<Finding> {
    if !ctx.mode.is_active() {
        return vec![Finding::pass(
            "open_redirect",
            1,
            "Open redirect no probado (modo pasivo)",
            cat::INJECTION,
        )
        .summary("Activa el modo PoC para probar redirecciones abiertas.")];
    }

    let params = [
        "redirect", "url", "next", "return", "returnUrl", "redirect_uri", "continue",
    ];
    let Ok(nc) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()
    else {
        return vec![Finding::pass(
            "open_redirect",
            1,
            "Open redirect no evaluable",
            cat::INJECTION,
        )
        .summary("No se pudo crear el cliente de prueba.")];
    };

    for p in params {
        let mut url = ctx.page.final_url.clone();
        url.query_pairs_mut().clear().append_pair(p, REDIRECT_TARGET);
        if let Ok(r) = nc.get(url.clone()).send().await {
            let st = r.status().as_u16();
            if (300..400).contains(&st) {
                let loc = r
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if loc.starts_with(REDIRECT_TARGET)
                    || loc.contains("vibeauditt-redirect-probe.example")
                {
                    return vec![Finding::new(
                        "open_redirect",
                        1,
                        "Open redirect",
                        cat::INJECTION,
                        Severity::Medium,
                    )
                    .summary(
                        "La app redirige a un dominio externo arbitrario según un parámetro de la \
                         URL.",
                    )
                    .add_evidence(format!("?{p}={REDIRECT_TARGET} → {st} Location: {loc}"))
                    .poc(format!(
                        "GET con ?{p}={REDIRECT_TARGET} devolvió {st} con Location hacia el dominio \
                         externo."
                    ))
                    .remediation(
                        "Valida los destinos de redirección contra una allowlist o usa solo rutas \
                         relativas. No redirijas a URLs absolutas controladas por el usuario.",
                    )
                    .prompt(format!(
                        "Mi app tiene un open redirect en el parámetro '{p}'. Implementa validación \
                         del destino con allowlist o fuerza rutas relativas."
                    ))
                    .refs(&["CWE-601: URL Redirection to Untrusted Site (Open Redirect)"])];
                }
            }
        }
    }

    vec![Finding::pass("open_redirect", 1, "Sin open redirect detectado", cat::INJECTION)
        .summary("Los parámetros de redirección comunes no llevaron a un dominio externo.")]
}
