use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};
use crate::engine::util::looks_like_html;

/// Detecta nombres de columnas sensibles (PII) en una fila JSON, sin volcar valores.
fn detect_pii(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(obj) = v.as_array().and_then(|a| a.first()).and_then(|o| o.as_object()) else {
        return Vec::new();
    };
    let sensitive = [
        "email", "mail", "phone", "tel", "password", "passwd", "token", "secret", "dni", "nif",
        "ssn", "address", "direccion", "card", "iban", "birth", "nacimiento",
    ];
    let mut out = Vec::new();
    for k in obj.keys() {
        let kl = k.to_lowercase();
        if sensitive.iter().any(|s| kl.contains(s)) {
            out.push(k.clone());
        }
    }
    out
}

static RE_SUPABASE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https://([a-z0-9]{16,})\.supabase\.co").unwrap());
static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}").unwrap()
});
static RE_FIREBASE_PROJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"projectId["']?\s*[:=]\s*["']([a-z0-9][a-z0-9-]{3,})["']"#).unwrap()
});

const COMMON_TABLES: &[&str] = &[
    "users", "profiles", "todos", "posts", "messages", "orders", "customers", "products",
    "subscriptions",
];

const COMMON_ENDPOINTS: &[&str] = &[
    "/api/users", "/api/admin", "/api/me", "/api/config", "/api/orders", "/api/customers",
    "/api/v1/users",
];

// ---------------------------------------------------------------------------
// Supabase / RLS
// ---------------------------------------------------------------------------
pub async fn supabase(ctx: &AuditContext) -> Vec<Finding> {
    let source = ctx.all_source();
    let Some(m) = RE_SUPABASE_URL.find(&source) else {
        return vec![Finding::pass("supabase_rls", 1, "Supabase no detectado", cat::AUTH)
            .summary("No se encontró un proyecto Supabase en el cliente.")];
    };
    let base = m.as_str().to_string();
    let anon = RE_JWT.find(&source).map(|j| j.as_str().to_string());

    // Pasivo, o sin anon key: solo detección.
    if !ctx.mode.is_active() || anon.is_none() {
        return vec![Finding::new(
            "supabase_rls",
            1,
            "Supabase detectado (verifica RLS)",
            cat::AUTH,
            Severity::Medium,
        )
        .summary(
            "Se usa Supabase desde el cliente. Si alguna tabla no tiene Row Level Security, sus \
             datos son legibles con la anon key pública.",
        )
        .add_evidence(format!("Proyecto: {base}"))
        .remediation(
            "Activa RLS en TODAS las tablas y define políticas explícitas. El modo activo (PoC) \
             puede confirmar si hay tablas legibles.",
        )
        .prompt(
            "Uso Supabase. Dame un checklist para verificar que todas mis tablas tienen Row Level \
             Security activado, con ejemplos de policy para que cada usuario solo lea sus filas.",
        )
        .refs(&["Supabase RLS", "OWASP A01:2021 — Broken Access Control"])];
    }

    // Activo / Profundo: PoC de lectura mínima con la anon key pública.
    let anon = anon.unwrap();

    // En modo profundo enumeramos TODAS las tablas vía el OpenAPI de Supabase.
    let mut tables: Vec<String> = Vec::new();
    if ctx.mode.is_deep() {
        if let Ok(r) = ctx
            .client
            .get(format!("{base}/rest/v1/"))
            .header("apikey", anon.as_str())
            .send()
            .await
        {
            if let Ok(text) = r.text().await {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    if let Some(defs) = v.get("definitions").and_then(|d| d.as_object()) {
                        tables.extend(defs.keys().cloned());
                    } else if let Some(paths) = v.get("paths").and_then(|p| p.as_object()) {
                        for k in paths.keys() {
                            let t = k.trim_start_matches('/');
                            if !t.is_empty() && !t.contains('{') {
                                tables.push(t.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    if tables.is_empty() {
        tables = COMMON_TABLES.iter().map(|s| s.to_string()).collect();
    }

    let mut readable: Vec<String> = Vec::new();
    let mut pii_cols: Vec<String> = Vec::new();
    for t in tables.iter().take(20) {
        let url = format!("{base}/rest/v1/{t}?select=*&limit=1");
        if let Ok(r) = ctx
            .client
            .get(&url)
            .header("apikey", anon.as_str())
            .header("authorization", format!("Bearer {anon}"))
            .send()
            .await
        {
            if r.status().is_success() {
                let body = r.text().await.unwrap_or_default();
                if body.trim_start().starts_with('[') {
                    let rows = if body.trim() == "[]" { 0 } else { 1 };
                    let pii = detect_pii(&body);
                    let extra = if pii.is_empty() {
                        String::new()
                    } else {
                        for c in &pii {
                            if !pii_cols.contains(c) {
                                pii_cols.push(c.clone());
                            }
                        }
                        format!(", PII: {}", pii.join(", "))
                    };
                    readable.push(format!("Tabla '{t}' legible ({rows} fila{extra})"));
                }
            }
        }
    }

    if readable.is_empty() {
        return vec![Finding::pass(
            "supabase_rls",
            1,
            "Supabase con RLS aparentemente activo",
            cat::AUTH,
        )
        .summary("Ninguna tabla probada fue legible con la anon key. RLS parece correcto.")
        .add_evidence(format!("Proyecto: {base}"))];
    }

    let pii_note = if pii_cols.is_empty() {
        String::new()
    } else {
        format!(" Se expone PII en columnas: {}.", pii_cols.join(", "))
    };

    vec![Finding::new(
        "supabase_rls",
        1,
        "Supabase sin RLS (tablas legibles públicamente)",
        cat::AUTH,
        Severity::Critical,
    )
    .summary(format!(
        "Se pudieron leer {} tabla(s) con la anon key pública: el Row Level Security está \
         desactivado o tiene políticas permisivas.{pii_note}",
        readable.len()
    ))
    .evidence(readable)
    .poc(format!(
        "GET {base}/rest/v1/<tabla>?select=*&limit=1 con la anon key → 200 con datos."
    ))
    .attack_chain(&[
        "Extraigo tu anon key pública del bundle JavaScript.",
        "Consulto /rest/v1/ y obtengo el esquema: todas tus tablas.",
        "Leo una muestra de cada tabla sin autenticarme (RLS desactivado).",
        "Exfiltro los datos (emails, perfiles, pedidos…) para spam, fraude o reventa.",
    ])
    .remediation(
        "Activa RLS (ALTER TABLE ... ENABLE ROW LEVEL SECURITY) y crea políticas que limiten cada \
         fila a su propietario. Nunca uses políticas USING (true) para lectura general.",
    )
    .prompt(
        "Tablas de Supabase son legibles con la anon key pública (RLS desactivado). Genera el SQL \
         para activar RLS en todas y una policy que restrinja el acceso a las filas del usuario \
         autenticado.",
    )
    .refs(&["Supabase Row Level Security", "CWE-284: Improper Access Control"])]
}

// ---------------------------------------------------------------------------
// Firebase
// ---------------------------------------------------------------------------
pub async fn firebase(ctx: &AuditContext) -> Vec<Finding> {
    let source = ctx.all_source();
    let has_fb = source.contains("firebaseio.com")
        || source.contains("firebaseapp.com")
        || source.contains("firestore.googleapis.com")
        || (source.contains("apiKey") && source.contains("authDomain"));
    let project = RE_FIREBASE_PROJECT
        .captures(&source)
        .and_then(|c| c.get(1))
        .map(|x| x.as_str().to_string());

    if !has_fb && project.is_none() {
        return vec![Finding::pass("firebase_rules", 1, "Firebase no detectado", cat::AUTH)
            .summary("No se encontró configuración de Firebase en el cliente.")];
    }

    let Some(pid) = project else {
        return vec![Finding::new(
            "firebase_rules",
            1,
            "Firebase detectado (verifica reglas)",
            cat::AUTH,
            Severity::Medium,
        )
        .summary("Se detectó Firebase pero no el projectId. Verifica que las reglas no sean abiertas.")
        .remediation("Revisa las reglas de Firestore/RTDB; nunca uses allow read, write: if true.")
        .prompt(
            "Uso Firebase. Dame reglas de seguridad de ejemplo para Firestore y Realtime Database \
             que exijan autenticación y propiedad del recurso.",
        )];
    };

    if !ctx.mode.is_active() {
        return vec![Finding::new(
            "firebase_rules",
            1,
            "Firebase detectado (verifica reglas)",
            cat::AUTH,
            Severity::Medium,
        )
        .summary(format!(
            "Proyecto Firebase '{pid}'. Si las reglas son abiertas, los datos son accesibles sin \
             autenticación. El modo activo puede confirmarlo."
        ))
        .add_evidence(format!("projectId: {pid}"))
        .remediation("Revisa reglas de Firestore/RTDB; exige request.auth != null y propiedad.")
        .prompt("Dame reglas seguras para Firestore y Realtime Database de mi proyecto Firebase.")];
    }

    // Activo: probar lectura de la Realtime DB sin auth (clásico .json).
    let mut open: Vec<String> = Vec::new();
    let candidates = [
        format!("https://{pid}-default-rtdb.firebaseio.com/.json"),
        format!("https://{pid}.firebaseio.com/.json"),
    ];
    for rtdb in candidates {
        if let Ok(r) = ctx.client.get(&rtdb).send().await {
            if r.status().is_success() {
                let body = r.text().await.unwrap_or_default();
                let b = body.trim();
                if b != "null" && !b.is_empty() && !body.contains("Permission denied") {
                    open.push(format!("Realtime DB legible sin auth: {rtdb}"));
                }
            }
        }
    }

    if open.is_empty() {
        return vec![Finding::pass(
            "firebase_rules",
            1,
            "Firebase con reglas restrictivas (RTDB)",
            cat::AUTH,
        )
        .summary(format!("La Realtime DB del proyecto '{pid}' no fue legible sin autenticación."))];
    }

    let first = open[0].clone();
    vec![Finding::new(
        "firebase_rules",
        1,
        "Firebase con reglas abiertas",
        cat::AUTH,
        Severity::Critical,
    )
    .summary("La base de datos de Firebase es legible sin autenticación: reglas abiertas.")
    .evidence(open)
    .poc(first)
    .remediation(
        "Cambia las reglas para exigir request.auth != null y validar la propiedad del dato. \
         Nunca uses 'if true' en read/write.",
    )
    .prompt(
        "Mi Realtime Database de Firebase es legible sin auth. Genera reglas seguras que exijan \
         autenticación y limiten el acceso a los datos del propio usuario.",
    )
    .refs(&["Firebase Security Rules", "CWE-284: Improper Access Control"])]
}

// ---------------------------------------------------------------------------
// Endpoints sin autenticación
// ---------------------------------------------------------------------------
pub async fn unauthed_endpoints(ctx: &AuditContext) -> Vec<Finding> {
    let mut hits: Vec<String> = Vec::new();
    let mut first_path = String::new();

    for ep in COMMON_ENDPOINTS {
        let Some(r) = ctx.get_path(ep).await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let ct = r
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = r.text().await.unwrap_or_default();
        if looks_like_html(&body) {
            continue; // fallback de la SPA, no un endpoint real
        }
        let trimmed = body.trim_start();
        let is_json =
            ct.contains("json") || trimmed.starts_with('{') || trimmed.starts_with('[');
        if is_json && body.trim().len() > 2 {
            if first_path.is_empty() {
                first_path = ep.to_string();
            }
            hits.push(format!("GET {ep} → 200, JSON de {} bytes sin autenticación", body.len()));
        }
    }

    if hits.is_empty() {
        return vec![Finding::pass(
            "unauthed_endpoints",
            1,
            "Sin endpoints abiertos evidentes",
            cat::AUTH,
        )
        .summary("Las rutas API comunes no devolvieron datos JSON sin autenticación.")];
    }

    vec![Finding::new(
        "unauthed_endpoints",
        1,
        "Endpoints API sin autenticación",
        cat::AUTH,
        Severity::High,
    )
    .summary("Hay endpoints que devuelven datos JSON sin pedir token de autenticación.")
    .evidence(hits)
    .poc(format!("GET {first_path} → 200 con JSON, sin cabecera Authorization."))
    .attack_chain(&[
        "Pruebo rutas de API comunes sin enviar ningún token.",
        "Encuentro endpoints que devuelven datos sin autenticación.",
        "Itero los IDs (IDOR) para extraer registros de todos los usuarios.",
    ])
    .remediation(
        "Exige autenticación y autorización en todos los endpoints que devuelvan datos. Verifica \
         el token en el servidor (middleware), nunca solo en el cliente.",
    )
    .prompt(format!(
        "El endpoint {first_path} devuelve datos sin autenticación. Añade verificación de token \
         (middleware) en mi backend y control de acceso por usuario."
    ))
    .refs(&[
        "OWASP API1:2023 — Broken Object Level Authorization",
        "CWE-306: Missing Authentication for Critical Function",
    ])]
}
