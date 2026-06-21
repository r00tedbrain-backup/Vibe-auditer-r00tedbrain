use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    // reqwest junta múltiples Set-Cookie; recorremos todos los valores.
    let cookies: Vec<String> = ctx
        .page
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    if cookies.is_empty() {
        return vec![Finding::pass(
            "cookie_flags",
            1,
            "Sin cookies inseguras",
            cat::COOKIES,
        )
        .summary("La respuesta principal no establece cookies en texto.")];
    }

    let mut problems = Vec::new();
    for c in &cookies {
        let lower = c.to_lowercase();
        let name = c.split('=').next().unwrap_or("cookie").trim();
        let mut missing = Vec::new();
        if !lower.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !lower.contains("secure") {
            missing.push("Secure");
        }
        if !lower.contains("samesite") {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            problems.push(format!("{name} → falta {}", missing.join(", ")));
        }
    }

    if problems.is_empty() {
        return vec![Finding::pass(
            "cookie_flags",
            1,
            "Cookies con flags correctos",
            cat::COOKIES,
        )
        .summary("Todas las cookies establecidas llevan HttpOnly, Secure y SameSite.")];
    }

    vec![Finding::new(
        "cookie_flags",
        1,
        "Cookies sin flags de seguridad",
        cat::COOKIES,
        Severity::Medium,
    )
    .summary("Hay cookies sin HttpOnly/Secure/SameSite, expuestas a robo (XSS) o envío cross-site.")
    .evidence(problems)
    .remediation(
        "Marca las cookies de sesión con HttpOnly, Secure y SameSite=Lax (o Strict). \
         HttpOnly impide el acceso desde JS, Secure las restringe a HTTPS y SameSite mitiga CSRF.",
    )
    .prompt(
        "Mis cookies de sesión no tienen los flags de seguridad. Configúralas con \
         HttpOnly, Secure y SameSite=Lax en mi backend y explica el efecto de cada flag.",
    )
    .refs(&["OWASP A05:2021 — Security Misconfiguration", "CWE-1004", "CWE-614"])]
}
