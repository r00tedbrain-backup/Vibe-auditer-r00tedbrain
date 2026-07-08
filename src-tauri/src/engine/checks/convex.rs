use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

static RE_CONVEX_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https://([a-z0-9-]+)\.convex\.cloud").unwrap());

// Referencias a funciones Convex del tipo "module:function" o "dir/module:fn".
static RE_CONVEX_FN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`]([a-z][a-zA-Z0-9_/]{0,40}:[a-zA-Z][a-zA-Z0-9_]{0,40})["'`]"#).unwrap()
});

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let source = ctx.all_source();
    let Some(m) = RE_CONVEX_URL.find(&source) else {
        return Vec::new(); // no usa Convex
    };
    let deployment = m.as_str().to_string();

    // Extraer candidatos de funciones del bundle.
    let mut fns: Vec<String> = Vec::new();
    for cap in RE_CONVEX_FN.captures_iter(&source) {
        let f = cap[1].to_string();
        if f.starts_with("http") || f.contains("//") {
            continue;
        }
        if !fns.contains(&f) {
            fns.push(f);
        }
        if fns.len() >= 40 {
            break;
        }
    }

    // Modo pasivo: solo detección.
    if !ctx.mode.is_active() {
        return vec![Finding::new(
            "convex_detected",
            1,
            "Backend Convex detectado (verifica autenticación)",
            cat::AUTH,
            Severity::Medium,
        )
        .summary(format!(
            "La app usa Convex ({deployment}). En Convex, cada función pública debe comprobar la \
             autenticación con ctx.auth.getUserIdentity(); si alguna no lo hace, cualquiera puede \
             llamarla sin token. Activa el modo PoC/profundo para probarlo."
        ))
        .add_evidence(format!("Deployment: {deployment}"))
        .add_evidence(format!("{} funciones referenciadas en el cliente", fns.len()))
        .remediation(
            "Comprueba que TODAS tus queries/mutations públicas verifiquen \
             ctx.auth.getUserIdentity() al inicio y filtren por el usuario. Convierte en \
             internalQuery/internalMutation lo que no deba llamarse desde el cliente.",
        )
        .prompt(
            "Uso Convex. Dame un checklist para verificar que todas mis funciones públicas \
             comprueban la autenticación, y cómo convertir en internal las que no deben ser \
             públicas.",
        )
        .refs(&["Convex Auth", "OWASP API5:2023 — Broken Function Level Authorization"])];
    }

    // Modo activo/profundo: probar SOLO queries (lectura) sin token.
    let query_url = format!("{deployment}/api/query");
    let mut readable: Vec<String> = Vec::new();
    for f in fns.iter().take(25) {
        let body = json!({ "path": f, "args": {}, "format": "json" }).to_string();
        let Ok(resp) = ctx
            .client
            .post(&query_url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
        else {
            continue;
        };
        let Ok(text) = resp.text().await else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v.get("status").and_then(|s| s.as_str()) != Some("success") {
            continue; // error (auth requerida, es mutation, args inválidos…): no vulnerable
        }
        // Se ejecutó sin token y devolvió un valor con datos.
        let has_data = v
            .get("value")
            .map(|x| match x {
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
                Value::Null => false,
                _ => true,
            })
            .unwrap_or(false);
        if has_data {
            readable.push(f.clone());
        }
    }

    if readable.is_empty() {
        return vec![Finding::new(
            "convex_detected",
            1,
            "Convex detectado (funciones de lectura protegidas)",
            cat::AUTH,
            Severity::Info,
        )
        .summary(format!(
            "La app usa Convex ({deployment}). Las funciones de lectura probadas sin token no \
             devolvieron datos: parecen requerir autenticación."
        ))
        .add_evidence(format!("Deployment: {deployment}; {} funciones probadas", fns.len().min(25)))];
    }

    let first = readable[0].clone();
    vec![Finding::new(
        "convex_unauth",
        1,
        "Funciones Convex públicas sin autenticación",
        cat::AUTH,
        Severity::Critical,
    )
    .summary(format!(
        "{} función(es) de Convex devuelven datos SIN token de autenticación. Cualquiera puede \
         leerlos llamando al HTTP API.",
        readable.len()
    ))
    .evidence(readable.iter().map(|f| format!("query «{f}» → datos sin auth")).collect())
    .poc(format!(
        "POST {deployment}/api/query con {{\"path\":\"{first}\",\"args\":{{}}}} y sin cabecera \
         Authorization devuelve datos."
    ))
    .attack_chain(&[
        "Extraigo el deployment Convex y los nombres de funciones de tu bundle JavaScript.",
        "Llamo /api/query con cada función sin token de autenticación.",
        "Las que no comprueban ctx.auth.getUserIdentity() me devuelven todos sus datos.",
        "Exfiltro los datos de tus usuarios/jugadores (posiciones, perfiles, inventario…).",
    ])
    .remediation(
        "Añade al inicio de cada query/mutation pública: `const identity = await \
         ctx.auth.getUserIdentity(); if (!identity) throw new Error(\"Not authenticated\");` y \
         filtra los datos por ese usuario. Convierte en internalQuery lo que no deba ser público.",
    )
    .prompt(format!(
        "La función Convex «{first}» devuelve datos sin autenticación. Añade la comprobación \
         ctx.auth.getUserIdentity() y el filtrado por usuario, y dime qué funciones deberían ser \
         internal en lugar de públicas."
    ))
    .refs(&[
        "Convex Authentication",
        "OWASP API5:2023 — Broken Function Level Authorization",
        "CWE-306: Missing Authentication",
    ])]
}
