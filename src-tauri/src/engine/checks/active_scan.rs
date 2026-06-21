use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use scraper::{Html, Selector};
use url::Url;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

/// Firmas de errores SQL (en minúsculas).
const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysqli",
    "warning: mysql_",
    "mysql_fetch",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "unterminated quoted string at or near",
    "syntax error at or near",
    "pg::syntaxerror",
    "psycopg2.errors",
    "sqlstate[",
    "sqlite3::",
    "sqlite_error",
    "ora-00933",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "npgsql.postgresexception",
    "pdoexception",
    "system.data.sqlclient.sqlexception",
];

/// Firmas de errores NoSQL (MongoDB).
const MONGO_ERRORS: &[&str] = &[
    "mongoerror",
    "mongoservererror",
    "casterror",
    "bsonerror",
    "e11000 duplicate",
    "unknown operator",
    "$where",
];

// Payloads NO destructivos (solo provocan error o lectura; nunca modifican datos).
const SQLI_PAYLOADS: &[&str] = &["'", "')", "1' OR '1'='1"];
const SSTI_PAYLOADS: &[(&str, &str)] = &[
    ("{{1337*1337}}", "1787569"),
    ("${1337*1337}", "1787569"),
    ("<%=1337*1337%>", "1787569"),
];
const CMDI_PAYLOADS: &[&str] = &[";id", "|id"];

const BLIND_JSON_FIELDS: &[&str] = &["q", "search", "id", "email", "username"];

static RE_URL_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:https?://[^\s"'<>)]+|/[A-Za-z0-9_\-./]+)\?[A-Za-z0-9_\-]+=[^\s"'<>)&]*(?:&[A-Za-z0-9_\-]+=[^\s"'<>)&]*)*"#).unwrap()
});
static RE_API_ROUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](/api/[A-Za-z0-9_\-/]{1,60})["'`]"#).unwrap());

#[derive(Clone, Copy, PartialEq)]
enum Method {
    Get,
    PostForm,
    PostJson,
}

struct Point {
    url: Url,
    method: Method,
    param: String,
    fields: Vec<(String, String)>,
}

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    // Parte pasiva (siempre): errores de DB ya filtrados en la respuesta.
    let mut findings = passive_db_errors(ctx);

    // Parte activa (solo modo profundo): inyección no destructiva.
    if !ctx.mode.is_deep() {
        return findings;
    }

    let points = collect_targets(ctx);
    for point in points.iter().take(8) {
        findings.extend(test_injection(ctx, point).await);
    }
    findings
}

fn passive_db_errors(ctx: &AuditContext) -> Vec<Finding> {
    let src = ctx.all_source().to_lowercase();
    let hit = SQL_ERRORS.iter().chain(MONGO_ERRORS.iter()).find(|s| src.contains(**s));
    if let Some(sig) = hit {
        return vec![Finding::new(
            "db_error_leak",
            1,
            "Errores de base de datos filtrados",
            cat::INJECTION,
            Severity::Medium,
        )
        .summary(
            "La aplicación filtra mensajes de error de la base de datos, revelando su tipo y \
             estructura interna a un atacante.",
        )
        .add_evidence(format!("Firma de error detectada: «{sig}»"))
        .remediation(
            "Desactiva los mensajes de error detallados en producción; muestra errores genéricos al \
             usuario y registra el detalle solo en el servidor.",
        )
        .prompt(
            "Mi app filtra errores de base de datos al cliente. Dime cómo desactivar los errores \
             verbosos en producción para mi stack.",
        )
        .refs(&["CWE-209: Sensitive Information in Error Message"])];
    }
    Vec::new()
}

fn collect_targets(ctx: &AuditContext) -> Vec<Point> {
    let final_url = &ctx.page.final_url;
    let host = final_url.host_str().map(|s| s.to_string());
    let source = ctx.all_source();
    let mut points = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // 1) Parámetros GET encontrados en HTML/bundle.
    for m in RE_URL_QUERY.find_iter(&source).take(300) {
        if points.len() >= 12 {
            break;
        }
        let Ok(u) = final_url.join(m.as_str()) else {
            continue;
        };
        if u.host_str().map(|s| s.to_string()) != host {
            continue;
        }
        let fields: Vec<(String, String)> =
            u.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let mut endpoint = u.clone();
        endpoint.set_query(None);
        for (k, _) in &fields {
            if k.is_empty() {
                continue;
            }
            if seen.insert(format!("GET|{}|{k}", endpoint.path())) {
                points.push(Point {
                    url: endpoint.clone(),
                    method: Method::Get,
                    param: k.clone(),
                    fields: fields.clone(),
                });
            }
        }
    }

    // 2) Formularios del HTML (GET y POST).
    let doc = Html::parse_document(&ctx.page.html);
    if let Ok(form_sel) = Selector::parse("form") {
        if let Ok(input_sel) = Selector::parse("input[name], textarea[name], select[name]") {
            for form in doc.select(&form_sel) {
                if points.len() >= 12 {
                    break;
                }
                let action = form.value().attr("action").unwrap_or("");
                let post = form
                    .value()
                    .attr("method")
                    .map(|m| m.eq_ignore_ascii_case("post"))
                    .unwrap_or(false);
                let target = if action.is_empty() { final_url.as_str() } else { action };
                let Ok(action_url) = final_url.join(target) else {
                    continue;
                };
                if action_url.host_str().map(|s| s.to_string()) != host {
                    continue;
                }
                let fields: Vec<(String, String)> = form
                    .select(&input_sel)
                    .filter_map(|i| {
                        i.value()
                            .attr("name")
                            .map(|n| (n.to_string(), i.value().attr("value").unwrap_or("1").to_string()))
                    })
                    .collect();
                if fields.is_empty() {
                    continue;
                }
                let method = if post { Method::PostForm } else { Method::Get };
                for (k, _) in &fields {
                    if seen.insert(format!("FORM|{}|{k}", action_url.path())) {
                        points.push(Point {
                            url: action_url.clone(),
                            method,
                            param: k.clone(),
                            fields: fields.clone(),
                        });
                    }
                }
            }
        }
    }

    // 3) Endpoints /api/ del bundle: POST JSON a ciegas con campos comunes.
    for cap in RE_API_ROUTE.captures_iter(&source).take(8) {
        if points.len() >= 12 {
            break;
        }
        let Ok(u) = final_url.join(&cap[1]) else {
            continue;
        };
        if u.host_str().map(|s| s.to_string()) != host {
            continue;
        }
        for field in BLIND_JSON_FIELDS {
            if seen.insert(format!("JSON|{}|{field}", u.path())) {
                points.push(Point {
                    url: u.clone(),
                    method: Method::PostJson,
                    param: (*field).to_string(),
                    fields: vec![((*field).to_string(), "test".to_string())],
                });
            }
        }
    }

    points
}

/// Envía la petición con el parámetro objetivo sustituido por `payload`.
async fn send(ctx: &AuditContext, point: &Point, payload: &str) -> Option<String> {
    let req = match point.method {
        Method::Get => {
            let mut u = point.url.clone();
            {
                let mut qp = u.query_pairs_mut();
                qp.clear();
                for (k, v) in &point.fields {
                    qp.append_pair(k, if *k == point.param { payload } else { v });
                }
            }
            ctx.client.get(u)
        }
        Method::PostForm => {
            let form: Vec<(&str, &str)> = point
                .fields
                .iter()
                .map(|(k, v)| (k.as_str(), if *k == point.param { payload } else { v.as_str() }))
                .collect();
            ctx.client.post(point.url.clone()).form(&form)
        }
        Method::PostJson => {
            let mut map = serde_json::Map::new();
            for (k, v) in &point.fields {
                let val = if *k == point.param { payload } else { v.as_str() };
                map.insert(k.clone(), serde_json::Value::String(val.to_string()));
            }
            ctx.client
                .post(point.url.clone())
                .header("content-type", "application/json")
                .body(serde_json::Value::Object(map).to_string())
        }
    };
    req.send().await.ok()?.text().await.ok()
}

async fn test_injection(ctx: &AuditContext, point: &Point) -> Vec<Finding> {
    let original = point
        .fields
        .iter()
        .find(|(k, _)| *k == point.param)
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let baseline = send(ctx, point, &original).await.unwrap_or_default().to_lowercase();

    let mut out = Vec::new();
    let loc = location(point);

    // SQL / NoSQL injection (error-based)
    let mut sql_done = false;
    let mut mongo_done = false;
    for payload in SQLI_PAYLOADS {
        if sql_done && mongo_done {
            break;
        }
        let Some(body) = send(ctx, point, payload).await else {
            continue;
        };
        let low = body.to_lowercase();
        if !sql_done {
            if let Some(sig) = SQL_ERRORS.iter().find(|s| low.contains(**s) && !baseline.contains(**s)) {
                out.push(sqli_finding(point, payload, sig, &loc));
                sql_done = true;
            }
        }
        if !mongo_done {
            if let Some(sig) = MONGO_ERRORS.iter().find(|s| low.contains(**s) && !baseline.contains(**s)) {
                out.push(nosqli_finding(point, payload, sig, &loc));
                mongo_done = true;
            }
        }
    }

    // Server-Side Template Injection
    for (payload, marker) in SSTI_PAYLOADS {
        let Some(body) = send(ctx, point, payload).await else {
            continue;
        };
        if body.contains(marker) && !baseline.contains(marker) {
            out.push(ssti_finding(point, payload, marker, &loc));
            break;
        }
    }

    // Command injection
    for payload in CMDI_PAYLOADS {
        let Some(body) = send(ctx, point, payload).await else {
            continue;
        };
        let low = body.to_lowercase();
        if low.contains("uid=") && low.contains("gid=") && !baseline.contains("uid=") {
            out.push(cmdi_finding(point, payload, &loc));
            break;
        }
    }

    out
}

fn location(point: &Point) -> String {
    let m = match point.method {
        Method::Get => "GET",
        Method::PostForm => "POST(form)",
        Method::PostJson => "POST(json)",
    };
    format!("{m} {} [param: {}]", point.url.path(), point.param)
}

fn sqli_finding(point: &Point, payload: &str, sig: &str, loc: &str) -> Finding {
    Finding::new("sqli", 1, "Inyección SQL (error-based)", cat::INJECTION, Severity::Critical)
        .summary(format!(
            "El parámetro «{}» es vulnerable a inyección SQL: un payload provocó un error de base de datos.",
            point.param
        ))
        .add_evidence(format!("{loc} con «{payload}» → error de DB: «{sig}»"))
        .poc(format!(
            "Inyectando «{payload}» en {loc} la base de datos devuelve un error de sintaxis (sin modificar datos)."
        ))
        .attack_chain(&[
            "Inyecto una comilla en el parámetro y observo un error de SQL.",
            "Confirmo que la entrada llega sin sanear a una consulta.",
            "Con UNION/boolean/time extraigo el contenido de tu base de datos.",
            "Llego a credenciales, datos de usuarios y, según permisos, a RCE.",
        ])
        .remediation(
            "Usa consultas parametrizadas (prepared statements) o un ORM; nunca concatenes entrada \
             del usuario en SQL. Aplica validación estricta de tipos.",
        )
        .prompt(format!(
            "El parámetro «{}» de mi API es vulnerable a SQL injection. Reescríbelo con consultas \
             parametrizadas/ORM y muéstrame el antes y el después.",
            point.param
        ))
        .refs(&["OWASP A03:2021 — Injection", "CWE-89: SQL Injection"])
}

fn nosqli_finding(point: &Point, payload: &str, sig: &str, loc: &str) -> Finding {
    Finding::new("nosqli", 1, "Inyección NoSQL", cat::INJECTION, Severity::Critical)
        .summary(format!(
            "El parámetro «{}» es vulnerable a inyección NoSQL: un payload provocó un error de MongoDB.",
            point.param
        ))
        .add_evidence(format!("{loc} con «{payload}» → error NoSQL: «{sig}»"))
        .poc(format!("Inyectando «{payload}» en {loc} la base de datos NoSQL devuelve un error."))
        .attack_chain(&[
            "Inyecto operadores ($ne, $gt) o rompo la sintaxis y observo un error de MongoDB.",
            "Uso operadores para saltarme autenticación o filtros (login bypass).",
            "Extraigo documentos de colecciones que no debería poder leer.",
        ])
        .remediation(
            "Valida y castea los tipos de entrada; rechaza objetos/operadores donde esperas strings. \
             Usa una capa de validación de esquema (zod, joi, mongoose con strict).",
        )
        .prompt(format!(
            "El parámetro «{}» es vulnerable a NoSQL injection. Añade validación de tipos/esquema y \
             rechaza operadores en mi backend.",
            point.param
        ))
        .refs(&["OWASP A03:2021 — Injection", "CWE-943: Improper Neutralization in a Data Query"])
}

fn ssti_finding(point: &Point, payload: &str, marker: &str, loc: &str) -> Finding {
    Finding::new("ssti", 1, "Server-Side Template Injection", cat::INJECTION, Severity::Critical)
        .summary(format!(
            "El parámetro «{}» evalúa expresiones de plantilla en el servidor (SSTI).",
            point.param
        ))
        .add_evidence(format!("{loc} con «{payload}» → la respuesta contiene {marker} (1337×1337)"))
        .poc(format!("Inyectando «{payload}» el servidor evaluó la operación y devolvió {marker}."))
        .attack_chain(&[
            "Inyecto una expresión matemática de plantilla y el servidor la evalúa.",
            "Escalo a lectura de variables internas y objetos del runtime.",
            "En muchos motores, SSTI lleva directamente a ejecución de código (RCE).",
        ])
        .remediation(
            "No pases entrada del usuario al motor de plantillas. Usa plantillas con autoescape y \
             separa datos de lógica.",
        )
        .prompt(format!(
            "El parámetro «{}» es vulnerable a SSTI. Dime cómo evitar que la entrada llegue al motor \
             de plantillas en mi framework.",
            point.param
        ))
        .refs(&["CWE-1336: Server-Side Template Injection"])
}

fn cmdi_finding(point: &Point, payload: &str, loc: &str) -> Finding {
    Finding::new("cmdi", 1, "Inyección de comandos del sistema", cat::INJECTION, Severity::Critical)
        .summary(format!("El parámetro «{}» ejecuta comandos del sistema operativo.", point.param))
        .add_evidence(format!("{loc} con «{payload}» → la respuesta contiene la salida de `id` (uid=…)"))
        .poc(format!(
            "Inyectando «{payload}» el servidor ejecutó `id` y devolvió uid=/gid= (solo lectura, sin daño)."
        ))
        .attack_chain(&[
            "Inyecto un separador de comandos y la orden inocua `id`.",
            "El servidor ejecuta el comando y devuelve su salida.",
            "Escalo a ejecución arbitraria de comandos: control total del servidor.",
        ])
        .remediation(
            "Nunca pases entrada del usuario a comandos del sistema. Usa APIs nativas del lenguaje y, \
             si es inevitable, listas blancas estrictas y escaping.",
        )
        .prompt(format!(
            "El parámetro «{}» permite inyección de comandos. Reescribe la lógica para no invocar la \
             shell con entrada del usuario.",
            point.param
        ))
        .refs(&["CWE-78: OS Command Injection"])
}
