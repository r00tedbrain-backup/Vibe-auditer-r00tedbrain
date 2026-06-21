use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::ruleset::SecretRule;
use crate::engine::types::{Finding, Severity};
use crate::engine::util::redact;

static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}").unwrap()
});

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let source = ctx.all_source();
    let rules = &ctx.rules.secret_rules;
    let mut findings = Vec::new();

    // Una sola pasada con RegexSet sobre todo el HTML + bundles.
    let patterns: Vec<&str> = rules.iter().map(|r| r.regex.as_str()).collect();
    if let Ok(set) = RegexSet::new(&patterns) {
        for idx in set.matches(&source).into_iter() {
            let rule = &rules[idx];
            let Ok(re) = Regex::new(&rule.regex) else {
                continue;
            };
            let hits: Vec<String> = re
                .find_iter(&source)
                .take(3)
                .map(|m| redact(m.as_str(), 6))
                .collect();
            if hits.is_empty() {
                continue;
            }
            findings.push(make_finding(rule, hits));
        }
    }

    // JWT embebido: posible service_role (crítico) o anon key (informativo).
    let jwt_hits: Vec<&str> = RE_JWT.find_iter(&source).map(|m| m.as_str()).take(3).collect();
    if !jwt_hits.is_empty() {
        if source.contains("service_role") {
            findings.push(
                Finding::new(
                    "exposed_service_role",
                    1,
                    "Posible service_role key de Supabase expuesta",
                    cat::SECRETS,
                    Severity::Critical,
                )
                .summary(
                    "Se detectó un JWT junto a la cadena «service_role». Esa clave salta el Row \
                     Level Security y da acceso total a la base de datos.",
                )
                .evidence(jwt_hits.iter().map(|s| redact(s, 8)).collect())
                .poc("Se encontró un JWT con rol service_role en el código del cliente.")
                .attack_chain(&[
                    "Extraigo la service_role key del bundle JavaScript.",
                    "La uso como apikey contra /rest/v1/, saltándome el RLS.",
                    "Leo y modifico cualquier tabla: control total de tu base de datos.",
                ])
                .remediation(
                    "Elimina la service_role key del cliente AHORA y rótala en Supabase. Esta clave \
                     solo debe vivir en el servidor.",
                )
                .prompt(
                    "Detecté una posible service_role key de Supabase en el frontend. Quítala del \
                     cliente, rótala y usa la anon key + RLS en el navegador; reserva la \
                     service_role solo para el backend.",
                )
                .refs(&["CWE-798: Use of Hard-coded Credentials"]),
            );
        } else {
            findings.push(
                Finding::new("jwt_in_bundle", 1, "JWT embebido en el cliente", cat::SECRETS, Severity::Info)
                    .summary(
                        "Se encontró un JWT en el código. Suele ser una anon key pública (normal), \
                         pero conviene confirmar que no es un token con privilegios.",
                    )
                    .evidence(jwt_hits.iter().map(|s| redact(s, 8)).collect())
                    .remediation(
                        "Verifica el rol del token. Si es la anon key de Supabase, es correcto \
                         siempre que tengas RLS activado.",
                    )
                    .prompt(
                        "Encontré un JWT en mi bundle. Ayúdame a decodificar su payload para \
                         confirmar que es solo la anon key (rol anon) y no un token con privilegios.",
                    ),
            );
        }
    }

    if findings.is_empty() {
        findings.push(
            Finding::pass("exposed_secret", 1, "Sin claves ni secretos expuestos", cat::SECRETS)
                .summary(format!(
                    "No se detectaron secretos entre las {} reglas del catálogo.",
                    rules.len()
                )),
        );
    }

    findings
}

fn make_finding(rule: &SecretRule, hits: Vec<String>) -> Finding {
    if rule.severity == Severity::Info {
        Finding::new("public_key_info", 1, &rule.description, cat::SECRETS, Severity::Info)
            .summary(
                "Valor público por diseño detectado. No es una vulnerabilidad, pero verifica que \
                 tenga restricciones bien configuradas.",
            )
            .evidence(hits)
            .remediation("Restringe su uso por dominio/origen en el panel del proveedor.")
            .prompt("Revisa que esta clave pública tenga restricciones de dominio configuradas.")
    } else {
        Finding::new("exposed_secret", 1, &rule.description, cat::SECRETS, rule.severity)
            .summary(format!(
                "Se encontró «{}» embebido en el código público del cliente.",
                rule.description
            ))
            .evidence(hits)
            .poc(format!(
                "El patrón «{}» apareció en el bundle/HTML servido al navegador.",
                rule.description
            ))
            .attack_chain(&[
                "Analizo tu bundle JavaScript público.",
                "Extraigo el secreto embebido en texto claro.",
                "Lo uso para acceder a tu cuenta del proveedor (Stripe, AWS, base de datos…).",
            ])
            .remediation(
                "Mueve este secreto al backend o a variables de entorno del servidor. Rótalo de \
                 inmediato (asume que ya está comprometido) y nunca lo incluyas en bundles del \
                 navegador.",
            )
            .prompt(format!(
                "Encontré un secreto de tipo «{}» expuesto en el cliente. Muévelo a una variable de \
                 entorno del servidor, crea un endpoint backend que lo use, elimina las referencias \
                 en el frontend e indícame cómo rotar la clave.",
                rule.description
            ))
            .refs(&[
                "OWASP A07:2021 — Identification and Authentication Failures",
                "CWE-798: Use of Hard-coded Credentials",
            ])
    }
}
