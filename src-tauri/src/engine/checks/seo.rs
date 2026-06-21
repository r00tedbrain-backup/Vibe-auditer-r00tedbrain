use scraper::{Html, Selector};

use super::cat;
use crate::engine::context::AuditContext;
use crate::engine::types::{Finding, Severity};

pub async fn run(ctx: &AuditContext) -> Vec<Finding> {
    // Parseo síncrono (sin cruzar await): el Html se descarta antes de retornar.
    let missing = analyze(&ctx.page.html);

    if missing.is_empty() {
        return vec![Finding::pass(
            "meta_tags",
            1,
            "Meta tags sociales presentes",
            cat::SEO,
        )
        .summary("La página incluye Open Graph, Twitter Card y descripción.")];
    }

    vec![Finding::new(
        "meta_tags",
        1,
        "Meta tags OG / Twitter incompletos",
        cat::SEO,
        Severity::Low,
    )
    .summary("Faltan metadatos sociales: los enlaces compartidos se verán pobres o vacíos.")
    .evidence(missing)
    .remediation(
        "Añade og:title, og:description, og:image, twitter:card y una meta description \
         en el <head>. Usa una imagen OG de 1200×630.",
    )
    .prompt(
        "Genera las meta tags Open Graph y Twitter Card completas para mi página \
         (og:title, og:description, og:image 1200x630, twitter:card) y dime dónde ponerlas.",
    )
    .refs(&["The Open Graph protocol — ogp.me"])]
}

fn analyze(html: &str) -> Vec<String> {
    let doc = Html::parse_document(html);
    let mut missing = Vec::new();

    let has = |selector: &str| -> bool {
        Selector::parse(selector)
            .ok()
            .map(|s| doc.select(&s).next().is_some())
            .unwrap_or(false)
    };

    if !has(r#"meta[name="description"]"#) {
        missing.push("meta description".to_string());
    }
    if !has(r#"meta[property="og:title"]"#) {
        missing.push("og:title".to_string());
    }
    if !has(r#"meta[property="og:description"]"#) {
        missing.push("og:description".to_string());
    }
    if !has(r#"meta[property="og:image"]"#) {
        missing.push("og:image".to_string());
    }
    if !has(r#"meta[name="twitter:card"]"#) {
        missing.push("twitter:card".to_string());
    }
    if !has(r#"link[rel~="icon"]"#) {
        missing.push("favicon (link rel=icon)".to_string());
    }

    missing
}
