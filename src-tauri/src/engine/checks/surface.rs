use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use regex::Regex;
use serde_json::Value;

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};
use crate::engine::util::looks_like_html;

static RE_ROUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](/api/[A-Za-z0-9_\-/]{1,60})["'`]"#).unwrap());

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    if !ctx.mode.is_deep() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    if let Some(f) = graphql(ctx).await {
        findings.push(f);
    }
    if let Some(f) = swagger(ctx).await {
        findings.push(f);
    }
    if let Some(f) = http_methods(ctx).await {
        findings.push(f);
    }
    if let Some(f) = robots(ctx).await {
        findings.push(f);
    }
    if let Some(f) = bundle_routes(ctx) {
        findings.push(f);
    }
    findings.extend(subdomains(ctx).await);

    if findings.is_empty() {
        findings.push(
            Finding::pass("surface", 1, "Superficie de ataque acotada", cat::CONFIG).summary(
                "No se descubrió superficie adicional (GraphQL, Swagger, subdominios) en el modo profundo.",
            ),
        );
    }
    findings
}

async fn graphql(ctx: &AuditContext) -> Option<Finding> {
    let body = r#"{"query":"query{__schema{queryType{name} types{name}}}"}"#;
    for path in ["/graphql", "/api/graphql", "/v1/graphql", "/query"] {
        let Ok(url) = ctx.page.final_url.join(path) else {
            continue;
        };
        let Ok(resp) = ctx
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
        else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(text) = resp.text().await else { continue };
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if v.pointer("/data/__schema").is_some() {
                let types = v
                    .pointer("/data/__schema/types")
                    .and_then(|t| t.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                return Some(
                    Finding::new(
                        "graphql_introspection",
                        1,
                        "GraphQL introspection habilitada",
                        cat::AUTH,
                        Severity::Medium,
                    )
                    .summary(
                        "El endpoint GraphQL permite introspección: se puede mapear todo el esquema \
                         (tipos, queries y mutations).",
                    )
                    .add_evidence(format!("POST {path} → __schema accesible ({types} tipos)"))
                    .poc(format!("POST {path} con query de introspección devolvió el esquema completo."))
                    .attack_chain(&[
                        "Envío una query de introspección a tu endpoint GraphQL.",
                        "Obtengo el esquema completo: tipos, queries y mutations.",
                        "Localizo mutations sensibles (updateUser, deleteX) y campos ocultos.",
                        "Construyo queries dirigidas para extraer o alterar datos.",
                    ])
                    .remediation(
                        "Desactiva la introspección en producción y aplica control de acceso por \
                         campo y rate limiting.",
                    )
                    .prompt(
                        "Mi endpoint GraphQL permite introspección en producción. Dime cómo \
                         desactivarla (Apollo/Yoga/etc.) y proteger las mutations sensibles.",
                    )
                    .refs(&["OWASP API3:2023 — Broken Object Property Level Authorization"]),
                );
            }
        }
    }
    None
}

async fn swagger(ctx: &AuditContext) -> Option<Finding> {
    for path in [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/v3/api-docs",
        "/swagger/v1/swagger.json",
    ] {
        let Some(resp) = ctx.get_path(path).await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(text) = resp.text().await else { continue };
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if v.get("openapi").is_some() || v.get("swagger").is_some() {
                let paths = v
                    .get("paths")
                    .and_then(|p| p.as_object())
                    .map(|o| o.len())
                    .unwrap_or(0);
                return Some(
                    Finding::new(
                        "openapi_exposed",
                        1,
                        "Especificación OpenAPI/Swagger expuesta",
                        cat::CONFIG,
                        Severity::Low,
                    )
                    .summary(
                        "La documentación OpenAPI/Swagger es pública: revela todos los endpoints, \
                         parámetros y modelos de la API.",
                    )
                    .add_evidence(format!("GET {path} → 200, {paths} endpoints documentados"))
                    .poc(format!("GET {path} devuelve la especificación con {paths} rutas."))
                    .attack_chain(&[
                        "Descargo tu especificación OpenAPI pública.",
                        "Mapeo todos los endpoints, parámetros y modelos sin adivinar.",
                        "Pruebo cada endpoint buscando los que no exigen autenticación.",
                    ])
                    .remediation("No publiques la spec en producción o protégela tras autenticación.")
                    .prompt(
                        "Mi especificación OpenAPI/Swagger es pública. Dime cómo restringir su \
                         acceso en producción.",
                    ),
                );
            }
        }
    }
    None
}

async fn http_methods(ctx: &AuditContext) -> Option<Finding> {
    let resp = ctx
        .client
        .request(reqwest::Method::OPTIONS, ctx.page.final_url.clone())
        .send()
        .await
        .ok()?;
    let allow = resp.headers().get("allow").and_then(|v| v.to_str().ok())?.to_string();
    let upper = allow.to_uppercase();
    let dangerous: Vec<&str> = ["PUT", "DELETE", "TRACE", "PATCH", "CONNECT"]
        .into_iter()
        .filter(|m| upper.contains(*m))
        .collect();
    if dangerous.is_empty() {
        return None;
    }
    let sev = if upper.contains("TRACE") {
        Severity::Medium
    } else {
        Severity::Low
    };
    Some(
        Finding::new(
            "http_methods",
            1,
            "Métodos HTTP peligrosos habilitados",
            cat::CONFIG,
            sev,
        )
        .summary("El servidor anuncia métodos que permiten modificación o ataques (TRACE → XST).")
        .add_evidence(format!("OPTIONS → Allow: {allow}"))
        .remediation("Limita los métodos a los necesarios (GET/POST) y desactiva TRACE.")
        .prompt(format!(
            "Mi servidor permite los métodos {}. Dime cómo restringirlos a los necesarios y \
             desactivar TRACE.",
            dangerous.join(", ")
        )),
    )
}

async fn robots(ctx: &AuditContext) -> Option<Finding> {
    let resp = ctx.get_path("/robots.txt").await?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if looks_like_html(&body) {
        return None;
    }
    let interesting: Vec<String> = body
        .lines()
        .filter(|l| l.to_lowercase().trim_start().starts_with("disallow:"))
        .map(|l| l.trim().to_string())
        .filter(|l| {
            let ll = l.to_lowercase();
            ll.contains("admin")
                || ll.contains("api")
                || ll.contains("internal")
                || ll.contains("private")
                || ll.contains("dashboard")
                || ll.contains("config")
                || ll.contains("backup")
        })
        .take(10)
        .collect();
    if interesting.is_empty() {
        return None;
    }
    Some(
        Finding::new(
            "robots_paths",
            1,
            "robots.txt revela rutas sensibles",
            cat::CONFIG,
            Severity::Info,
        )
        .summary("robots.txt lista rutas internas/sensibles, dando pistas directas a un atacante.")
        .evidence(interesting)
        .remediation(
            "No uses robots.txt para ocultar rutas sensibles; protégelas con autenticación. \
             robots.txt es público por definición.",
        )
        .prompt(
            "Mi robots.txt revela rutas sensibles. Dime cómo protegerlas con autenticación en vez \
             de listarlas.",
        ),
    )
}

fn bundle_routes(ctx: &AuditContext) -> Option<Finding> {
    let source = ctx.all_source();
    let mut routes: Vec<String> = Vec::new();
    for cap in RE_ROUTE.captures_iter(&source) {
        let r = cap[1].to_string();
        if !routes.contains(&r) {
            routes.push(r);
        }
        if routes.len() >= 25 {
            break;
        }
    }
    if routes.len() < 2 {
        return None;
    }
    Some(
        Finding::new(
            "bundle_routes",
            1,
            "Rutas internas de API descubiertas en el bundle",
            cat::CONFIG,
            Severity::Info,
        )
        .summary(format!(
            "Se extrajeron {} rutas de API del JavaScript del cliente: un mapa de tu superficie de \
             ataque.",
            routes.len()
        ))
        .evidence(routes)
        .attack_chain(&[
            "Descargo y analizo tu bundle JavaScript.",
            "Extraigo todas las rutas /api/ referenciadas en el código.",
            "Pruebo cada ruta buscando endpoints sin autenticación o con IDOR.",
        ])
        .remediation(
            "El cliente conocerá sus rutas; asegúrate de que TODAS exijan autenticación y \
             autorización en el servidor.",
        )
        .prompt(
            "Estas rutas de API aparecen en mi bundle. Ayúdame a verificar que todas exigen \
             autenticación y control de acceso en el backend.",
        ),
    )
}

/// Sufijos de plataformas (PaaS) donde cada usuario tiene un subdominio.
/// Si el target está bajo uno de estos, su "dominio" es el host completo y
/// enumerar hermanos del sufijo daría falsos positivos (son de la plataforma).
const PAAS_SUFFIXES: &[&str] = &[
    "vercel.app", "netlify.app", "herokuapp.com", "github.io", "pages.dev", "web.app",
    "firebaseapp.com", "onrender.com", "fly.dev", "railway.app", "workers.dev", "surge.sh",
    "now.sh", "repl.co", "replit.app", "glitch.me", "amplifyapp.com", "azurewebsites.net",
    "appspot.com", "ondigitalocean.app", "supabase.co", "pythonanywhere.com", "deno.dev",
];

/// Dominio del usuario sobre el que enumerar subdominios, o None si es un sitio
/// de plataforma (PaaS) sin subdominios propios genéricos.
fn registrable_base(host: &str) -> Option<String> {
    for suffix in PAAS_SUFFIXES {
        if host == *suffix {
            return None;
        }
        if let Some(stripped) = host.strip_suffix(&format!(".{suffix}")) {
            // host = "proyecto.vercel.app" → sitio PaaS, no enumeramos hermanos.
            if !stripped.contains('.') {
                return None;
            }
        }
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[parts.len() - 2..].join("."))
    } else {
        None
    }
}

async fn subdomains(ctx: &AuditContext) -> Vec<Finding> {
    let host = ctx.host();
    let Some(base) = registrable_base(&host) else {
        return Vec::new(); // sitio PaaS: no enumeramos subdominios de la plataforma
    };

    let Ok(nc) = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return Vec::new();
    };

    // Detección de wildcard: si un subdominio aleatorio responde, no es fiable.
    let canary = format!("https://vibeauditt-nx9q7z3k.{base}/");
    if let Ok(r) = nc.get(&canary).send().await {
        if r.status().as_u16() < 500 {
            return Vec::new();
        }
    }

    // Candidatos: Certificate Transparency (crt.sh) + prefijos comunes.
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for s in crtsh_subdomains(&ctx.client, &base).await {
        candidates.insert(s);
    }
    for p in [
        "api", "admin", "staging", "dev", "test", "portal", "app", "dashboard", "internal",
        "beta", "cdn", "auth",
    ] {
        candidates.insert(format!("{p}.{base}"));
    }
    candidates.remove(&host);

    // Verificamos qué subdominios están activos, en paralelo (rápido).
    let found: Vec<String> = stream::iter(candidates.into_iter().take(50))
        .map(|sub| {
            let nc = &nc;
            async move {
                match nc.get(format!("https://{sub}/")).send().await {
                    Ok(r) if r.status().as_u16() < 500 => Some(sub),
                    _ => None,
                }
            }
        })
        .buffer_unordered(12)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    if found.is_empty() {
        return Vec::new();
    }
    let mut found = found;
    found.sort();

    let mut findings = vec![Finding::new(
        "subdomains",
        1,
        "Subdominios adicionales accesibles",
        cat::CONFIG,
        Severity::Info,
    )
    .summary(format!(
        "Se encontraron {} subdominios activos de tu dominio. Cada uno amplía la superficie de \
         ataque y se audita a continuación.",
        found.len()
    ))
    .evidence(found.iter().map(|s| format!("{s} (activo)")).collect())
    .attack_chain(&[
        "Enumero subdominios comunes de tu dominio (api, admin, staging, dev).",
        "Los entornos de staging/dev suelen tener menos protecciones y datos reales.",
        "Busco en ellos credenciales, paneles sin auth o versiones vulnerables.",
    ])
    .remediation(
        "Revisa que los subdominios de staging/dev no sean públicos ni contengan datos reales; \
         protégelos con auth, allowlist de IP o VPN.",
    )
    .prompt(
        "Tengo subdominios (staging/dev/admin) accesibles públicamente. Dime cómo restringir su \
         acceso (auth, allowlist de IP o VPN).",
    )];

    // Auditamos cada subdominio real con los checks clave, etiquetando los hallazgos.
    for sub in found.iter().take(5) {
        let Ok(sub_url) = url::Url::parse(&format!("https://{sub}/")) else {
            continue;
        };
        let Ok(subctx) =
            AuditContext::fetch(ctx.client.clone(), sub_url, ctx.mode, ctx.rules.clone()).await
        else {
            continue;
        };

        let mut subf = Vec::new();
        subf.extend(super::headers::run(&subctx).await);
        subf.extend(super::secrets::run(&subctx).await);
        subf.extend(super::exposed_files::git(&subctx).await);
        subf.extend(super::cors::run(&subctx).await);

        for mut f in subf {
            if f.severity == Severity::Clean {
                continue;
            }
            f.title = format!("{sub} · {}", f.title);
            findings.push(f);
        }
    }

    findings
}

/// Descubre subdominios reales desde los logs de Certificate Transparency (crt.sh).
async fn crtsh_subdomains(client: &reqwest::Client, base: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%25.{base}&output=json");
    let Ok(resp) = client.get(&url).timeout(Duration::from_secs(25)).send().await else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(text) = resp.text().await else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&text) else {
        return Vec::new();
    };

    let mut set: BTreeSet<String> = BTreeSet::new();
    for item in arr.iter().take(3000) {
        if let Some(nv) = item.get("name_value").and_then(|v| v.as_str()) {
            for name in nv.split('\n') {
                let n = name.trim().trim_start_matches("*.").to_lowercase();
                if !n.is_empty() && n != base && n.ends_with(base) && !n.contains('*') {
                    set.insert(n);
                }
            }
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::registrable_base;

    #[test]
    fn paas_hosts_are_not_enumerated() {
        assert_eq!(registrable_base("gaia-copilot.vercel.app"), None);
        assert_eq!(registrable_base("foo.netlify.app"), None);
        assert_eq!(registrable_base("myproj.supabase.co"), None);
    }

    #[test]
    fn real_domains_resolve_to_registrable() {
        assert_eq!(registrable_base("miempresa.com"), Some("miempresa.com".into()));
        assert_eq!(registrable_base("www.miempresa.com"), Some("miempresa.com".into()));
    }
}
