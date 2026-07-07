use std::time::Instant;

use chrono::Utc;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::engine::context::build_client;
use crate::engine::score::{counts_from, grade_from, score_from_findings};
use crate::engine::types::{AuditMode, AuditReport, Finding, Severity};

const CAT: &str = "API";

/// Rutas de API comunes a probar cuando no hay contrato OpenAPI.
const API_PATHS: &[&str] = &[
    "users", "user", "accounts", "auth", "login", "register", "me", "profile", "admin",
    "products", "orders", "customers", "items", "cart", "payments", "invoices", "config",
    "settings", "health", "status", "version", "search", "files", "notifications", "messages",
    "posts", "comments", "roles", "permissions", "tokens", "keys", "logs", "debug", "graphql",
    "v1/users", "v1/auth", "api/users", "api/admin", "swagger.json", "openapi.json", "api-docs",
];

const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg::syntaxerror",
    "sqlstate[",
    "sqlite_error",
    "ora-00933",
    "odbc sql server driver",
    "mongoerror",
    "mongoservererror",
];

const PII_KEYS: &[&str] = &[
    "email", "mail", "phone", "tel", "password", "passwd", "token", "secret", "dni", "nif",
    "ssn", "address", "iban", "card",
];

pub async fn scan_api(base_raw: &str, _mode: AuditMode) -> Result<AuditReport, String> {
    let started = Instant::now();
    let base = normalize(base_raw)?;
    let client = build_client().map_err(|e| format!("No se pudo crear el cliente HTTP: {e}"))?;

    let mut findings = Vec::new();

    // 1) Descubrir contrato OpenAPI/Swagger.
    let mut endpoints: Vec<Url> = Vec::new();
    if let Some((spec_url, paths)) = discover_openapi(&client, &base).await {
        findings.push(
            Finding::new("api_openapi", 1, "Especificación OpenAPI/Swagger expuesta", CAT, Severity::Low)
                .summary(format!("La API publica su especificación en {spec_url} ({} rutas).", paths.len()))
                .add_evidence(format!("{spec_url} → {} endpoints documentados", paths.len()))
                .remediation("No publiques la especificación en producción o protégela tras autenticación.")
                .prompt("Mi API expone su OpenAPI/Swagger públicamente. Dime cómo restringir su acceso."),
        );
        for p in paths {
            if let Some(u) = make_url(&base, &p) {
                endpoints.push(u);
            }
        }
    }

    // 2) Wordlist de rutas comunes.
    for p in API_PATHS {
        if let Some(u) = make_url(&base, p) {
            if !endpoints.iter().any(|e| e.as_str() == u.as_str()) {
                endpoints.push(u);
            }
        }
    }
    endpoints.truncate(60);

    // 3) Detectar endpoints vivos en paralelo.
    let live: Vec<Url> = stream::iter(endpoints)
        .map(|u| {
            let client = &client;
            async move {
                match client.get(u.clone()).send().await {
                    Ok(r) => {
                        let s = r.status().as_u16();
                        if s != 404 && s < 500 {
                            Some(u)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
        })
        .buffer_unordered(12)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    if live.is_empty() {
        findings.push(
            Finding::pass("api_scan", 1, "No se encontraron endpoints", CAT)
                .summary("No respondió ninguna ruta de API común en esta URL base."),
        );
    }

    // 4) Analizar cada endpoint vivo (limitado).
    for ep in live.iter().take(20) {
        findings.extend(analyze_endpoint(&client, ep).await);
    }

    // 5) CORS a nivel de la API.
    findings.extend(check_cors(&client, &base).await);

    if findings.iter().all(|f| f.severity == Severity::Clean || f.severity == Severity::Info) {
        findings.push(
            Finding::pass("api_scan", 1, "Sin vulnerabilidades evidentes en la API", CAT)
                .summary("Los endpoints detectados no revelaron datos sin auth, inyección ni CORS inseguro."),
        );
    }

    let counts = counts_from(&findings);
    let score = score_from_findings(&findings);
    let grade = grade_from(score);
    findings.sort_by_key(|f| sev_rank(f.severity));

    Ok(AuditReport {
        id: Uuid::new_v4().to_string(),
        url: base.to_string(),
        final_url: base.to_string(),
        mode: AuditMode::Deep,
        created_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        score,
        grade,
        counts,
        checks_run: 5,
        findings,
    })
}

async fn analyze_endpoint(client: &Client, url: &Url) -> Vec<Finding> {
    let mut out = Vec::new();
    let path = url.path().to_string();

    let Ok(resp) = client.get(url.clone()).send().await else {
        return out;
    };
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().await.unwrap_or_default();
    let trimmed = body.trim_start();
    let is_json = ct.contains("json") || trimmed.starts_with('{') || trimmed.starts_with('[');

    // Endpoint que devuelve datos sin autenticación.
    if status == 200 && is_json && body.trim().len() > 2 {
        let pii = detect_pii(&body);
        let sev = if pii.is_empty() { Severity::Medium } else { Severity::High };
        let pii_note = if pii.is_empty() {
            String::new()
        } else {
            format!(" Expone posible PII: {}.", pii.join(", "))
        };
        out.push(
            Finding::new("api_unauth", 1, "Endpoint accesible sin autenticación", CAT, sev)
                .summary(format!(
                    "{path} devuelve datos JSON sin pedir token de autenticación.{pii_note}"
                ))
                .add_evidence(format!("GET {path} → 200, {} bytes de JSON", body.len()))
                .poc(format!("GET {path} sin cabecera Authorization devuelve datos."))
                .attack_chain(&[
                    "Llamo al endpoint sin ningún token.",
                    "Recibo datos que deberían requerir autenticación.",
                    "Itero IDs y parámetros para extraer todos los registros.",
                ])
                .remediation(
                    "Exige autenticación y autorización en el servidor para todo endpoint que \
                     devuelva datos. Verifica el token en un middleware, no en el cliente.",
                )
                .prompt(format!(
                    "El endpoint {path} de mi API devuelve datos sin autenticación. Añade \
                     verificación de token (middleware) y control de acceso por usuario."
                ))
                .refs(&["OWASP API1:2023 / API5:2023", "CWE-306: Missing Authentication"]),
        );
    }

    // Inyección error-based en parámetros comunes.
    'inj: for param in ["id", "q", "search", "user"] {
        for payload in ["'", "1'\""] {
            let mut u = url.clone();
            u.query_pairs_mut().clear().append_pair(param, payload);
            if let Ok(r) = client.get(u).send().await {
                let low = r.text().await.unwrap_or_default().to_lowercase();
                if let Some(sig) = SQL_ERRORS.iter().find(|s| low.contains(**s)) {
                    let nosql = sig.contains("mongo");
                    out.push(injection_finding(&path, param, payload, sig, nosql));
                    break 'inj;
                }
            }
        }
    }

    out
}

fn injection_finding(path: &str, param: &str, payload: &str, sig: &str, nosql: bool) -> Finding {
    let (id, title, refs): (&str, &str, &[&str]) = if nosql {
        ("api_nosqli", "Inyección NoSQL en la API", &["CWE-943", "OWASP API8:2023"])
    } else {
        ("api_sqli", "Inyección SQL en la API", &["CWE-89", "OWASP API8:2023"])
    };
    Finding::new(id, 1, title, CAT, Severity::Critical)
        .summary(format!("El parámetro «{param}» de {path} es vulnerable a inyección (error de BD)."))
        .add_evidence(format!("GET {path}?{param}={payload} → error de BD: «{sig}»"))
        .poc(format!("Inyectando «{payload}» en {param} la base de datos devuelve un error (sin modificar datos)."))
        .attack_chain(&[
            "Inyecto una comilla en un parámetro y observo un error de base de datos.",
            "Confirmo que la entrada llega sin sanear a la consulta.",
            "Extraigo el contenido de la base de datos con técnicas UNION/boolean/time.",
        ])
        .remediation("Usa consultas parametrizadas/ORM y valida los tipos de entrada. Nunca concatenes entrada del usuario.")
        .prompt(format!("El parámetro «{param}» de mi API ({path}) es vulnerable a inyección. Reescríbelo con consultas parametrizadas."))
        .refs(refs)
}

async fn check_cors(client: &Client, base: &Url) -> Vec<Finding> {
    let probe = "https://vibeauditt-cors-probe.example";
    let Ok(resp) = client.get(base.clone()).header("origin", probe).send().await else {
        return Vec::new();
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
        return Vec::new();
    };
    if !(v == "*" || v == probe) {
        return Vec::new();
    }
    let sev = if acac { Severity::High } else { Severity::Medium };
    vec![Finding::new("api_cors", 1, "CORS permisivo en la API", CAT, sev)
        .summary(if acac {
            "La API refleja el Origin y permite credenciales: cualquier web puede leer datos autenticados."
        } else {
            "La API responde Access-Control-Allow-Origin abierto: cualquier web puede leer sus respuestas."
        })
        .add_evidence(format!("Origin: {probe} → ACAO: {v}; Allow-Credentials: {acac}"))
        .poc(format!("Con Origin: {probe} la API devuelve ACAO: {v}."))
        .remediation("Restringe Access-Control-Allow-Origin a una allowlist de tus dominios y no combines '*' con credenciales.")
        .prompt("Mi API tiene CORS permisivo. Configura una allowlist de orígenes de confianza.")
        .refs(&["CWE-942: Permissive Cross-domain Policy"])]
}

async fn discover_openapi(client: &Client, base: &Url) -> Option<(String, Vec<String>)> {
    for p in ["openapi.json", "swagger.json", "v3/api-docs", "api-docs", "swagger/v1/swagger.json"] {
        let Some(u) = make_url(base, p) else { continue };
        let Ok(r) = client.get(u.clone()).send().await else { continue };
        if !r.status().is_success() {
            continue;
        }
        let Ok(text) = r.text().await else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        if v.get("openapi").is_none() && v.get("swagger").is_none() {
            continue;
        }
        let paths: Vec<String> = v
            .get("paths")
            .and_then(|p| p.as_object())
            .map(|o| o.keys().filter(|k| !k.contains('{')).cloned().collect())
            .unwrap_or_default();
        return Some((u.to_string(), paths));
    }
    None
}

fn detect_pii(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let obj = v
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .or_else(|| v.as_object());
    let Some(obj) = obj else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in obj.keys() {
        let kl = k.to_lowercase();
        if PII_KEYS.iter().any(|s| kl.contains(s)) {
            out.push(k.clone());
        }
    }
    out
}

fn make_url(base: &Url, path: &str) -> Option<Url> {
    let b = base.as_str().trim_end_matches('/');
    let p = path.trim_start_matches('/');
    Url::parse(&format!("{b}/{p}")).ok()
}

fn normalize(raw: &str) -> Result<Url, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("Ingresa la URL base de la API.".into());
    }
    let with_scheme = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    };
    let u = Url::parse(&with_scheme).map_err(|_| "URL inválida.".to_string())?;
    if u.host_str().is_none() {
        return Err("La URL no tiene un host válido.".into());
    }
    Ok(u)
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Clean => 5,
    }
}
