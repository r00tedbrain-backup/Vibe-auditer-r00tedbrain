use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

const PROBE_ORIGIN: &str = "https://vibeauditt-cors-probe.example";

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let resp = match ctx
        .client
        .get(ctx.page.final_url.clone())
        .header("origin", PROBE_ORIGIN)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return vec![Finding::pass("cors", 1, "CORS no evaluable", cat::CONFIG)
                .summary("No se pudo repetir la petición con un Origin de prueba.")];
        }
    };

    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let acac = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let Some(v) = acao else {
        return vec![Finding::pass("cors", 1, "CORS restrictivo", cat::CONFIG)
            .summary("La respuesta no expone Access-Control-Allow-Origin a orígenes externos.")];
    };

    let reflected = v == PROBE_ORIGIN;
    let wildcard = v == "*";

    if (reflected || wildcard) && acac {
        vec![Finding::new(
            "cors_misconfig",
            1,
            "CORS inseguro con credenciales",
            cat::CONFIG,
            Severity::High,
        )
        .summary(
            "La API refleja el Origin (o usa *) y además permite credenciales: cualquier web \
             podría leer datos autenticados de tus usuarios.",
        )
        .add_evidence(format!(
            "Origin: {PROBE_ORIGIN} → Access-Control-Allow-Origin: {v}; Allow-Credentials: true"
        ))
        .poc(format!(
            "Enviando Origin: {PROBE_ORIGIN}, la respuesta devuelve ACAO reflejado y \
             Allow-Credentials: true."
        ))
        .remediation(
            "No reflejes el Origin de forma dinámica junto con credenciales. Usa una allowlist \
             explícita de orígenes de confianza y nunca combines '*' con Allow-Credentials.",
        )
        .prompt(
            "Mi CORS refleja el Origin y permite credenciales. Implementa una allowlist de \
             orígenes de confianza en mi backend y corrige la cabecera Allow-Credentials.",
        )
        .refs(&["CWE-942: Permissive Cross-domain Policy with Untrusted Domains"])]
    } else if reflected || wildcard {
        vec![Finding::new(
            "cors_misconfig",
            1,
            "CORS permisivo",
            cat::CONFIG,
            Severity::Medium,
        )
        .summary(if wildcard {
            "La API responde Access-Control-Allow-Origin: * — cualquier web puede leer sus \
             respuestas (sin credenciales)."
        } else {
            "La API refleja cualquier Origin recibido en Access-Control-Allow-Origin."
        })
        .add_evidence(format!("Origin: {PROBE_ORIGIN} → Access-Control-Allow-Origin: {v}"))
        .poc(format!("Con Origin: {PROBE_ORIGIN}, la respuesta devuelve ACAO: {v}."))
        .remediation(
            "Restringe Access-Control-Allow-Origin a una allowlist de tus propios dominios.",
        )
        .prompt(
            "Configura CORS con una allowlist de orígenes propios en lugar de reflejar el Origin \
             o usar comodín.",
        )]
    } else {
        vec![Finding::pass("cors", 1, "CORS restrictivo", cat::CONFIG)
            .summary(format!("ACAO fijo ({v}); no refleja el Origin de prueba."))]
    }
}
