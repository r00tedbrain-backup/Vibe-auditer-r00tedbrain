/// Censura un valor sensible dejando solo los extremos visibles.
/// Ej: redact("sk_live_abcdef123456", 4) -> "sk_l…3456"
pub fn redact(s: &str, keep: usize) -> String {
    let n = s.chars().count();
    if n <= keep * 2 {
        return "*".repeat(n.max(3));
    }
    let start: String = s.chars().take(keep).collect();
    let end: String = s.chars().skip(n - keep).collect();
    format!("{start}…{end}")
}

/// Trunca una String a `max` bytes respetando los límites de carácter UTF-8.
pub fn truncate_bytes(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut idx = max;
        while idx > 0 && !s.is_char_boundary(idx) {
            idx -= 1;
        }
        s.truncate(idx);
    }
    s
}

/// Acorta una línea larga para mostrarla como evidencia.
pub fn snippet(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let head: String = trimmed.chars().take(max).collect();
        format!("{head}…")
    }
}

/// Heurística: ¿el cuerpo parece ser el index.html de una SPA (fallback)?
/// Sirve para descartar respuestas 200 que en realidad son la app, no el archivo.
pub fn looks_like_html(s: &str) -> bool {
    let head = s.get(..s.len().min(1024)).unwrap_or(s).to_lowercase();
    head.contains("<!doctype html") || head.contains("<html")
}
