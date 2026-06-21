use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::engine::types::Severity;

/// Fuentes públicas y vivas para actualizar el catálogo (sin infra propia).
pub const GITLEAKS_URL: &str =
    "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml";
pub const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRule {
    pub id: String,
    pub description: String,
    pub regex: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::High
}

/// Catálogo de detección: reglas de secretos + CVEs en explotación activa (KEV).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ruleset {
    pub version: String,
    pub secret_rules: Vec<SecretRule>,
    pub kev_cves: HashSet<String>,
}

impl Ruleset {
    /// Añade reglas que no existan (por id). Devuelve cuántas se añadieron.
    pub fn merge_secret_rules(&mut self, new_rules: Vec<SecretRule>) -> usize {
        let existing: HashSet<String> = self.secret_rules.iter().map(|r| r.id.clone()).collect();
        let mut added = 0;
        for r in new_rules {
            if !existing.contains(&r.id) {
                self.secret_rules.push(r);
                added += 1;
            }
        }
        added
    }

    /// Añade CVEs KEV nuevos. Devuelve cuántos se añadieron.
    pub fn merge_kev(&mut self, new_kev: HashSet<String>) -> usize {
        let before = self.kev_cves.len();
        self.kev_cves.extend(new_kev);
        self.kev_cves.len() - before
    }
}

/// Reglas de secretos base, embebidas en la app (funcionan sin actualizar).
pub fn base_ruleset() -> Ruleset {
    let rule = |id: &str, description: &str, regex: &str, severity: Severity| SecretRule {
        id: id.to_string(),
        description: description.to_string(),
        regex: regex.to_string(),
        severity,
    };

    Ruleset {
        version: "base".to_string(),
        secret_rules: vec![
            rule("stripe-live", "Clave secreta de Stripe (live)", r"sk_live_[0-9a-zA-Z]{20,}", Severity::Critical),
            rule("stripe-test", "Clave secreta de Stripe (test)", r"sk_test_[0-9a-zA-Z]{20,}", Severity::High),
            rule("stripe-restricted", "Restricted key de Stripe (live)", r"rk_live_[0-9a-zA-Z]{20,}", Severity::Critical),
            rule("openai-project", "API key de OpenAI (proyecto)", r"sk-proj-[A-Za-z0-9_\-]{20,}", Severity::Critical),
            rule("aws-access-key", "AWS Access Key ID", r"AKIA[0-9A-Z]{16}", Severity::Critical),
            rule("google-api-key", "Google / Firebase API key", r"AIza[0-9A-Za-z\-_]{35}", Severity::Medium),
            rule("github-pat", "GitHub Personal Access Token", r"ghp_[0-9A-Za-z]{36}", Severity::Critical),
            rule("slack-token", "Token de Slack", r"xox[baprs]-[0-9A-Za-z\-]{10,}", Severity::High),
            rule("private-key-pem", "Clave privada (PEM)", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", Severity::Critical),
            rule("db-connection-string", "Cadena de conexión a base de datos con credenciales", r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@", Severity::Critical),
            rule("stripe-publishable", "Clave publicable de Stripe (pública por diseño)", r"pk_live_[0-9a-zA-Z]{20,}", Severity::Info),
        ],
        kev_cves: HashSet::new(),
    }
}

#[derive(Deserialize)]
struct GitleaksConfig {
    #[serde(default)]
    rules: Vec<GitleaksRule>,
}

#[derive(Deserialize)]
struct GitleaksRule {
    id: Option<String>,
    description: Option<String>,
    regex: Option<String>,
}

/// Parsea el gitleaks.toml y devuelve reglas de secretos cuya regex compila en Rust.
pub fn parse_gitleaks(toml_text: &str) -> Vec<SecretRule> {
    let Ok(cfg) = toml::from_str::<GitleaksConfig>(toml_text) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for r in cfg.rules {
        let (Some(id), Some(regex)) = (r.id, r.regex) else {
            continue;
        };
        if id.is_empty() || regex.is_empty() {
            continue;
        }
        // La regex de gitleaks es sintaxis Go (RE2); descartamos las que no compilen en Rust.
        if regex::Regex::new(&regex).is_err() {
            continue;
        }
        let description = r.description.unwrap_or_else(|| id.clone());
        out.push(SecretRule {
            id: format!("gitleaks:{id}"),
            description,
            regex,
            severity: Severity::High,
        });
    }
    out
}

/// Parsea el feed CISA KEV y devuelve el conjunto de CVE IDs en explotación activa.
pub fn parse_kev(json_text: &str) -> HashSet<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return HashSet::new();
    };
    let mut set = HashSet::new();
    if let Some(vulns) = v.get("vulnerabilities").and_then(|x| x.as_array()) {
        for item in vulns {
            if let Some(cve) = item.get("cveID").and_then(|x| x.as_str()) {
                set.insert(cve.to_string());
            }
        }
    }
    set
}
