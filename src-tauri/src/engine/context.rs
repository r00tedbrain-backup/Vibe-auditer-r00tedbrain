use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

use super::ruleset::Ruleset;
use super::types::AuditMode;
use super::util::truncate_bytes;

const USER_AGENT: &str =
    "VibeAuditt/0.1 (+https://vibeauditt.com; security self-audit)";
const MAX_BUNDLES: usize = 8;
const MAX_BODY_BYTES: usize = 3_000_000; // 3 MB por recurso

pub struct Bundle {
    pub url: String,
    pub body: String,
}

pub struct PageData {
    pub final_url: Url,
    pub headers: HeaderMap,
    pub html: String,
    pub bundles: Vec<Bundle>,
}

pub struct AuditContext {
    pub client: Client,
    pub mode: AuditMode,
    pub rules: Arc<Ruleset>,
    pub page: PageData,
}

pub fn build_client() -> reqwest::Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(8))
        .build()
}

impl AuditContext {
    /// Descarga la página objetivo, sus headers y los bundles JS referenciados.
    pub async fn fetch(
        client: Client,
        target: Url,
        mode: AuditMode,
        rules: Arc<Ruleset>,
    ) -> Result<Self, String> {
        let resp = client
            .get(target.clone())
            .send()
            .await
            .map_err(|e| format!("No se pudo conectar con la URL: {e}"))?;

        let final_url = Url::parse(resp.url().as_str()).unwrap_or_else(|_| target.clone());
        let headers = resp.headers().clone();
        let html = resp.text().await.unwrap_or_default();

        // Parseamos el HTML (sync, sin cruzar await) para sacar los <script src>.
        let script_srcs = extract_script_srcs(&html, &final_url);

        let mut bundles = Vec::new();
        for src in script_srcs.into_iter().take(MAX_BUNDLES) {
            if let Ok(b) = client.get(&src).send().await {
                if let Ok(body) = b.text().await {
                    bundles.push(Bundle {
                        url: src,
                        body: truncate_bytes(body, MAX_BODY_BYTES),
                    });
                }
            }
        }

        Ok(AuditContext {
            client,
            mode,
            rules,
            page: PageData {
                final_url,
                headers,
                html,
                bundles,
            },
        })
    }

    /// GET a una ruta relativa al origen del objetivo. None si falla la conexión.
    pub async fn get_path(&self, path: &str) -> Option<reqwest::Response> {
        let url = self.page.final_url.join(path).ok()?;
        self.client.get(url).send().await.ok()
    }

    /// Valor de un header de la respuesta principal (case-insensitive).
    pub fn header(&self, name: &str) -> Option<String> {
        self.page
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    pub fn host(&self) -> String {
        self.page.final_url.host_str().unwrap_or("").to_string()
    }

    /// Texto combinado del HTML + todos los bundles (para buscar secretos).
    pub fn all_source(&self) -> String {
        let mut s = String::with_capacity(self.page.html.len() + 1024);
        s.push_str(&self.page.html);
        for b in &self.page.bundles {
            s.push('\n');
            s.push_str(&b.body);
        }
        s
    }
}

fn extract_script_srcs(html: &str, base: &Url) -> Vec<String> {
    let doc = Html::parse_document(html);
    let Ok(sel) = Selector::parse("script[src]") else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for el in doc.select(&sel) {
        if let Some(src) = el.value().attr("src") {
            if let Ok(abs) = base.join(src) {
                let s = abs.to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    }
    out
}
