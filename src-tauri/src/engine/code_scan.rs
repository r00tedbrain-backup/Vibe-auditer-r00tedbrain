use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

use chrono::Utc;
use regex::Regex;
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

use crate::engine::score::{counts_from, grade_from, score_from_findings};
use crate::engine::types::{AuditMode, AuditReport, Finding, Severity};

const CAT_SECRETS: &str = "Secretos";
const CAT_CONVEX: &str = "Convex / Backend";
const CAT_CODE: &str = "Código";
const CAT_CONFIG: &str = "Configuración";

const MAX_FILE_BYTES: u64 = 2_000_000;
const MAX_FINDINGS: usize = 400;
const IGNORED_DIRS: &[&str] = &[
    "node_modules", ".git", "dist", "build", ".next", ".expo", "target", "Pods", ".venv",
    "__pycache__", "vendor", ".turbo", "coverage", ".cache", ".idea", ".vscode",
];
const CODE_EXT: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "rb", "php", "go", "rs", "java", "kt", "swift",
    "json", "yaml", "yml", "rules", "toml", "sql", "sh",
];

struct SecretPat {
    re: Regex,
    desc: &'static str,
    sev: Severity,
}

static SECRET_PATS: LazyLock<Vec<SecretPat>> = LazyLock::new(|| {
    let p = |re: &str, desc: &'static str, sev: Severity| SecretPat {
        re: Regex::new(re).unwrap(),
        desc,
        sev,
    };
    vec![
        p(r"sk_live_[0-9a-zA-Z]{20,}", "Clave secreta de Stripe (live)", Severity::Critical),
        p(r"sk-proj-[A-Za-z0-9_\-]{20,}", "API key de OpenAI", Severity::Critical),
        p(r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity::Critical),
        p(r"AIza[0-9A-Za-z\-_]{35}", "Google / Firebase API key", Severity::Medium),
        p(r"ghp_[0-9A-Za-z]{36}", "GitHub token", Severity::Critical),
        p(r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Token de Slack", Severity::High),
        p(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----", "Clave privada (PEM)", Severity::Critical),
        p(r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@", "Cadena de conexión con credenciales", Severity::Critical),
    ]
});

struct DangerPat {
    re: Regex,
    title: &'static str,
    sev: Severity,
    remediation: &'static str,
}

static DANGER_PATS: LazyLock<Vec<DangerPat>> = LazyLock::new(|| {
    vec![
        DangerPat { re: Regex::new(r"\beval\s*\(").unwrap(), title: "Uso de eval()", sev: Severity::Medium, remediation: "Evita eval(); usa JSON.parse o lógica explícita." },
        DangerPat { re: Regex::new(r"dangerouslySetInnerHTML").unwrap(), title: "dangerouslySetInnerHTML (posible XSS)", sev: Severity::Medium, remediation: "Sanitiza el HTML (p.ej. DOMPurify) o evita insertar HTML del usuario." },
        DangerPat { re: Regex::new(r"(?:child_process|\bexecSync\s*\(|\bexec\s*\()").unwrap(), title: "Ejecución de comandos del sistema", sev: Severity::Medium, remediation: "No pases entrada del usuario a la shell; usa APIs nativas y listas blancas." },
        DangerPat { re: Regex::new(r"new\s+Function\s*\(").unwrap(), title: "new Function() (evaluación dinámica)", sev: Severity::Low, remediation: "Evita construir funciones desde cadenas de texto." },
    ]
});

static RE_CONVEX_FUNC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"export\s+const\s+(\w+)\s*=\s*(query|mutation|action)\s*\(").unwrap());
static RE_FIREBASE_OPEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"allow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true").unwrap());
static RE_ENV_VALUE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S{6,}").unwrap());

pub async fn scan_code(root: &str) -> Result<AuditReport, String> {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        return Err("La ruta seleccionada no es un directorio válido.".into());
    }
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut files_scanned = 0u32;

    for entry in WalkDir::new(root_path)
        .into_iter()
        .filter_entry(|e| !is_ignored(e))
        .filter_map(|e| e.ok())
    {
        if findings.len() > MAX_FINDINGS {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !is_code_file(path) {
            continue;
        }
        if entry.metadata().map(|m| m.len() > MAX_FILE_BYTES).unwrap_or(true) {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else { continue };
        files_scanned += 1;
        let rel = path
            .strip_prefix(root_path)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        findings.extend(scan_secrets(&rel, &content));
        findings.extend(scan_dangerous(&rel, &content));
        findings.extend(scan_convex(&rel, &content));
        findings.extend(scan_firebase(&rel, &content));
        findings.extend(scan_env(&rel, &content));
    }

    if files_scanned == 0 {
        return Err("No se encontraron archivos de código en esa carpeta.".into());
    }

    if findings.is_empty() {
        findings.push(Finding::pass("code_scan", 1, "Sin problemas evidentes en el código", CAT_CODE).summary(
            format!("Se analizaron {files_scanned} archivos y no se detectaron secretos, funciones sin auth ni patrones peligrosos."),
        ));
    }

    let counts = counts_from(&findings);
    let score = score_from_findings(&findings);
    let grade = grade_from(score);
    findings.sort_by_key(|f| sev_rank(f.severity));

    let name = root_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| root.to_string());

    Ok(AuditReport {
        id: Uuid::new_v4().to_string(),
        url: format!("code://{name}"),
        final_url: root.to_string(),
        mode: AuditMode::Deep,
        created_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        score,
        grade,
        counts,
        checks_run: files_scanned,
        findings,
    })
}

fn scan_secrets(rel: &str, content: &str) -> Vec<Finding> {
    if rel.ends_with(".example") || rel.ends_with(".sample") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pat in SECRET_PATS.iter() {
        if let Some(m) = pat.re.find(content) {
            if is_placeholder(m.as_str()) {
                continue;
            }
            let line = line_of(content, m.start());
            out.push(
                Finding::new("code_secret", 1, &format!("Secreto en código: {}", pat.desc), CAT_SECRETS, pat.sev)
                    .summary(format!("Se encontró «{}» hardcodeado en el código fuente.", pat.desc))
                    .add_evidence(format!("{rel}:{line} → {}", redact(m.as_str())))
                    .attack_chain(&[
                        "Descargo tu app o accedo a tu repositorio.",
                        "Extraigo el secreto embebido en el código.",
                        "Lo uso para acceder a tu cuenta del proveedor (Stripe, AWS, DB…).",
                    ])
                    .remediation("Mueve el secreto a variables de entorno del servidor (nunca en el cliente), rótalo de inmediato y asegúrate de que el archivo está en .gitignore.")
                    .prompt(format!("Tengo un secreto «{}» hardcodeado en {rel}. Muévelo a variables de entorno seguras, quítalo del cliente y dime cómo rotarlo.", pat.desc))
                    .refs(&["CWE-798: Use of Hard-coded Credentials"]),
            );
        }
    }
    out
}

fn scan_dangerous(rel: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for pat in DANGER_PATS.iter() {
        if let Some(m) = pat.re.find(content) {
            let line = line_of(content, m.start());
            out.push(
                Finding::new("code_dangerous", 1, pat.title, CAT_CODE, pat.sev)
                    .summary(format!("Patrón potencialmente peligroso en {rel}: {}.", pat.title))
                    .add_evidence(format!("{rel}:{line}"))
                    .remediation(pat.remediation)
                    .prompt(format!("En {rel} uso «{}». Revisa si es explotable y dame una alternativa segura.", pat.title)),
            );
        }
    }
    out
}

fn scan_convex(rel: &str, content: &str) -> Vec<Finding> {
    if !rel.contains("convex/") || (!rel.ends_with(".ts") && !rel.ends_with(".js")) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for cap in RE_CONVEX_FUNC.captures_iter(content) {
        let name = cap[1].to_string();
        let kind = cap[2].to_string();
        let start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let body = body_window(content, start);
        if body.contains("getUserIdentity") || body.contains("ctx.auth") {
            continue; // comprueba autenticación
        }
        let line = line_of(content, start);
        let sev = if kind == "mutation" || kind == "action" {
            Severity::Critical
        } else {
            Severity::High
        };
        out.push(
            Finding::new("convex_code_noauth", 1, &format!("Función Convex «{name}» sin comprobar autenticación"), CAT_CONVEX, sev)
                .summary(format!(
                    "La {kind} pública «{name}» no llama a ctx.auth.getUserIdentity(): cualquiera puede ejecutarla sin token vía el HTTP API de Convex."
                ))
                .add_evidence(format!("{rel}:{line} → export const {name} = {kind}(...)  (sin getUserIdentity)"))
                .attack_chain(&[
                    "Localizo el deployment Convex y el nombre de la función en tu app.",
                    "Llamo al HTTP API de Convex con esa función y sin token de autenticación.",
                    "Como no comprueba la identidad, me devuelve o modifica los datos.",
                    "Exfiltro o altero los datos de tus usuarios/jugadores.",
                ])
                .remediation("Añade al inicio del handler: `const identity = await ctx.auth.getUserIdentity(); if (!identity) throw new Error(\"Not authenticated\");` y filtra por ese usuario. Si no debe llamarse desde el cliente, usa internalQuery/internalMutation.")
                .prompt(format!("Mi función Convex «{name}» ({kind}) no comprueba la autenticación. Añade ctx.auth.getUserIdentity() y el filtrado por usuario, o conviértela en internal si no debe ser pública."))
                .refs(&["Convex Authentication", "OWASP API5:2023 — Broken Function Level Authorization", "CWE-306"]),
        );
    }
    out
}

fn scan_firebase(rel: &str, content: &str) -> Vec<Finding> {
    if !rel.contains("rules") && !rel.ends_with(".rules") {
        return Vec::new();
    }
    if RE_FIREBASE_OPEN.is_match(content) {
        let line = RE_FIREBASE_OPEN
            .find(content)
            .map(|m| line_of(content, m.start()))
            .unwrap_or(1);
        return vec![Finding::new("firebase_rules_open", 1, "Reglas de Firebase abiertas", CAT_CONFIG, Severity::Critical)
            .summary(format!("{rel} contiene reglas «allow ...: if true»: la base de datos es accesible sin autenticación."))
            .add_evidence(format!("{rel}:{line} → allow ...: if true"))
            .remediation("Cambia las reglas para exigir request.auth != null y validar la propiedad del dato. Nunca uses 'if true'.")
            .prompt("Mis reglas de Firebase usan 'if true'. Genera reglas seguras que exijan autenticación y limiten el acceso al propio usuario.")
            .refs(&["Firebase Security Rules", "CWE-284"])];
    }
    Vec::new()
}

fn scan_env(rel: &str, content: &str) -> Vec<Finding> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if !name.starts_with(".env") || name.contains("example") || name.contains("sample") {
        return Vec::new();
    }
    let count = RE_ENV_VALUE.find_iter(content).count();
    if count == 0 {
        return Vec::new();
    }
    vec![Finding::new("env_in_repo", 1, "Archivo .env con valores en el proyecto", CAT_CONFIG, Severity::Medium)
        .summary(format!("{rel} contiene {count} variables con valor. Si está commiteado en git, es una fuga de secretos."))
        .add_evidence(format!("{rel} → {count} variables con valor"))
        .remediation("Asegúrate de que .env está en .gitignore y nunca se commitea. Usa un .env.example con placeholders para el repositorio.")
        .prompt("Tengo un .env con valores en mi proyecto. Verifica que está en .gitignore y dime cómo eliminar secretos ya commiteados del historial de git.")
        .refs(&["CWE-538: File and Directory Information Exposure"])]
}

fn body_window(content: &str, start: usize) -> String {
    let window: String = content.get(start..).unwrap_or("").chars().take(1200).collect();
    match window.match_indices("export ").nth(1) {
        Some((i, _)) => window[..i].to_string(),
        None => window,
    }
}

fn line_of(content: &str, offset: usize) -> usize {
    content
        .get(..offset.min(content.len()))
        .map(|s| s.bytes().filter(|b| *b == b'\n').count() + 1)
        .unwrap_or(1)
}

fn is_placeholder(s: &str) -> bool {
    let l = s.to_lowercase();
    ["usuario", "contrase", "user:pass", "username:password", "example", "your", "<", "xxx", "changeme", "placeholder"]
        .iter()
        .any(|p| l.contains(p))
}

fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 10 {
        return "*".repeat(n.max(3));
    }
    let start: String = s.chars().take(6).collect();
    format!("{start}…****")
}

fn is_ignored(e: &DirEntry) -> bool {
    if !e.file_type().is_dir() {
        return false;
    }
    e.file_name()
        .to_str()
        .map(|n| IGNORED_DIRS.contains(&n))
        .unwrap_or(false)
}

fn is_code_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with(".env") {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| CODE_EXT.contains(&e))
        .unwrap_or(false)
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
