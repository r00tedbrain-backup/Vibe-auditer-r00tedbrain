use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    let src = ctx.all_source();
    let html = &ctx.page.html;
    let cookies = ctx
        .page
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ")
        .to_lowercase();

    let mut tech: Vec<String> = Vec::new();

    // Servidor / runtime declarado en cabeceras
    if let Some(s) = ctx.header("server") {
        tech.push(format!("Servidor: {s}"));
    }
    if let Some(s) = ctx.header("x-powered-by") {
        tech.push(format!("Powered-By: {s}"));
    }

    // Framework frontend (por firmas en el bundle/HTML)
    let framework = if src.contains("/_next/") || ctx.header("x-nextjs-cache").is_some() {
        Some("Next.js (React)")
    } else if src.contains("/_nuxt/") {
        Some("Nuxt (Vue)")
    } else if html.contains("data-astro-cid") || html.contains("data-astro") {
        Some("Astro")
    } else if src.contains("__sveltekit") || src.contains("/_app/immutable/") {
        Some("SvelteKit")
    } else if src.contains("__remixContext") {
        Some("Remix (React)")
    } else if src.contains("___gatsby") {
        Some("Gatsby (React)")
    } else if html.contains("ng-version") {
        Some("Angular")
    } else if src.contains("data-reactroot") || (src.contains("react-dom") && src.contains("react")) {
        Some("React")
    } else {
        None
    };
    if let Some(f) = framework {
        tech.push(format!("Framework: {f}"));
    }

    // CDN / WAF / hosting
    if ctx.header("cf-ray").is_some()
        || ctx.header("server").map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false)
    {
        tech.push("CDN/WAF: Cloudflare".into());
    }
    if ctx.header("x-vercel-id").is_some() {
        tech.push("Hosting: Vercel".into());
    }
    if ctx.header("x-nf-request-id").is_some() {
        tech.push("Hosting: Netlify".into());
    }
    if ctx.header("x-fastly-request-id").is_some()
        || ctx.header("x-served-by").map(|s| s.contains("cache")).unwrap_or(false)
    {
        tech.push("CDN: Fastly".into());
    }
    if ctx.header("x-amz-cf-id").is_some() {
        tech.push("CDN: AWS CloudFront".into());
    }
    if ctx.header("x-sucuri-id").is_some() {
        tech.push("WAF: Sucuri".into());
    }

    // Lenguaje / backend por cookies de sesión
    if cookies.contains("phpsessid") {
        tech.push("Lenguaje: PHP".into());
    }
    if cookies.contains("laravel_session") {
        tech.push("Framework: Laravel (PHP)".into());
    }
    if cookies.contains("csrftoken") || cookies.contains("sessionid") {
        tech.push("Framework: Django (Python)".into());
    }
    if cookies.contains("_rails") || cookies.contains("_session_id") {
        tech.push("Framework: Ruby on Rails".into());
    }
    if cookies.contains("connect.sid") {
        tech.push("Backend: Express (Node.js)".into());
    }
    if cookies.contains("aspxauth") || cookies.contains("asp.net") {
        tech.push("Backend: ASP.NET".into());
    }
    if cookies.contains("jsessionid") {
        tech.push("Backend: Java (Servlet)".into());
    }

    // Backend-as-a-service / API
    if src.contains(".supabase.co") {
        tech.push("Backend: Supabase (PostgreSQL)".into());
    }
    if src.contains("firebaseio.com")
        || src.contains("firebaseapp.com")
        || src.contains("firestore.googleapis.com")
    {
        tech.push("Backend: Firebase".into());
    }
    if src.contains("hasura") || ctx.header("x-hasura-role").is_some() {
        tech.push("API: Hasura (GraphQL)".into());
    }
    if src.contains("appwrite") {
        tech.push("Backend: Appwrite".into());
    }
    if src.contains("pocketbase") {
        tech.push("Backend: PocketBase".into());
    }
    if src.contains("convex.cloud") {
        tech.push("Backend: Convex".into());
    }

    // Servicios de terceros
    if src.contains("googletagmanager") || src.contains("google-analytics") {
        tech.push("Analytics: Google".into());
    }
    if src.contains("js.sentry") || src.contains("@sentry") {
        tech.push("Monitoring: Sentry".into());
    }
    if src.contains("js.stripe.com") {
        tech.push("Pagos: Stripe".into());
    }

    if tech.is_empty() {
        return vec![Finding::pass("tech_fingerprint", 1, "Stack no identificado", cat::CONFIG)
            .summary("No se identificaron tecnologías concretas por firmas.")];
    }

    vec![Finding::new(
        "tech_fingerprint",
        1,
        "Tecnología detectada",
        cat::CONFIG,
        Severity::Info,
    )
    .summary(
        "Resumen del stack identificado. No es una vulnerabilidad en sí, pero revela tu superficie \
         y ayuda a un atacante a dirigir el ataque. Nota: la base de datos solo se identifica si la \
         app la expone al cliente (Supabase/Firebase); una API con BD propia oculta no es visible \
         desde fuera (lo cual es correcto).",
    )
    .evidence(tech)
    .remediation(
        "Reduce la exposición de versiones y tecnología (cabeceras Server / X-Powered-By, banners) \
         para dificultar el fingerprinting de un atacante.",
    )
    .prompt(
        "Dame recomendaciones para reducir el fingerprinting de mi stack: ocultar versiones de \
         servidor y framework y las cabeceras reveladoras.",
    )]
}
