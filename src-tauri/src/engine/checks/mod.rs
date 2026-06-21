use futures::future::BoxFuture;

use super::context::AuditContext;
use super::types::Finding;

pub mod active_scan;
pub mod backends;
pub mod client_side;
pub mod cookies;
pub mod cors;
pub mod deps_cve;
pub mod exposed_files;
pub mod fingerprint;
pub mod headers;
pub mod injection;
pub mod secrets;
pub mod seo;
pub mod surface;
pub mod tls;

/// Categorías mostradas en el reporte.
pub mod cat {
    pub const SECRETS: &str = "Secretos";
    pub const CONFIG: &str = "Configuración";
    pub const HEADERS: &str = "Headers HTTP";
    pub const AUTH: &str = "Autenticación";
    pub const TLS: &str = "TLS / HTTPS";
    pub const CLIENT: &str = "Cliente / Bundle";
    pub const INJECTION: &str = "Inyección";
    pub const COOKIES: &str = "Cookies / Sesión";
    pub const SEO: &str = "SEO técnico";
}

pub type CheckFn = for<'a> fn(&'a AuditContext) -> BoxFuture<'a, Vec<Finding>>;

pub struct CheckDef {
    pub name: &'static str,
    pub run: CheckFn,
}

/// Registro de checks. Para añadir uno nuevo, escribe la función
/// `async fn run(ctx) -> Vec<Finding>` y añádela aquí.
pub fn registry() -> Vec<CheckDef> {
    vec![
        CheckDef {
            name: "Tecnología y stack",
            run: |c| Box::pin(fingerprint::run(c)),
        },
        CheckDef {
            name: "Claves y secretos expuestos",
            run: |c| Box::pin(secrets::run(c)),
        },
        CheckDef {
            name: "Archivos sensibles expuestos",
            run: |c| Box::pin(exposed_files::run(c)),
        },
        CheckDef {
            name: "Directorio .git expuesto",
            run: |c| Box::pin(exposed_files::git(c)),
        },
        CheckDef {
            name: "Headers de seguridad",
            run: |c| Box::pin(headers::run(c)),
        },
        CheckDef {
            name: "Configuración CORS",
            run: |c| Box::pin(cors::run(c)),
        },
        CheckDef {
            name: "TLS / HTTPS",
            run: |c| Box::pin(tls::run(c)),
        },
        CheckDef {
            name: "Supabase / Row Level Security",
            run: |c| Box::pin(backends::supabase(c)),
        },
        CheckDef {
            name: "Firebase",
            run: |c| Box::pin(backends::firebase(c)),
        },
        CheckDef {
            name: "Endpoints sin autenticación",
            run: |c| Box::pin(backends::unauthed_endpoints(c)),
        },
        CheckDef {
            name: "Cookies y sesión",
            run: |c| Box::pin(cookies::run(c)),
        },
        CheckDef {
            name: "Source maps y calidad del bundle",
            run: |c| Box::pin(client_side::run(c)),
        },
        CheckDef {
            name: "XSS reflejado (canary)",
            run: |c| Box::pin(injection::reflected(c)),
        },
        CheckDef {
            name: "Open redirect",
            run: |c| Box::pin(injection::open_redirect(c)),
        },
        CheckDef {
            name: "Meta tags y SEO técnico",
            run: |c| Box::pin(seo::run(c)),
        },
        CheckDef {
            name: "Dependencias vulnerables (CVE / OSV)",
            run: |c| Box::pin(deps_cve::run(c)),
        },
        CheckDef {
            name: "Enumeración de superficie (pentest)",
            run: |c| Box::pin(surface::run(c)),
        },
        CheckDef {
            name: "Inyección: SQLi / SSTI / comandos",
            run: |c| Box::pin(active_scan::run(c)),
        },
    ]
}
