use printpdf::{BuiltinFont, IndirectFontRef, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference};

use crate::engine::types::{AuditMode, AuditReport, Confidence, Finding, Severity};

const PAGE_W: f64 = 210.0;
const PAGE_H: f64 = 297.0;
const MARGIN: f64 = 18.0;
const TOP: f64 = PAGE_H - MARGIN;
const BOTTOM: f64 = MARGIN;
const LINE_H: f64 = 5.0;
const MAX_CHARS: usize = 96;

struct Pdf {
    doc: PdfDocumentReference,
    font: IndirectFontRef,
    bold: IndirectFontRef,
    mono: IndirectFontRef,
    layer: PdfLayerReference,
    y: f64,
}

impl Pdf {
    fn new() -> Result<Self, String> {
        let (doc, page, layer_idx) = PdfDocument::new(
            "VibeAuditt — Informe de seguridad",
            Mm(PAGE_W as f32),
            Mm(PAGE_H as f32),
            "Capa 1",
        );
        let font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
        let bold = doc.add_builtin_font(BuiltinFont::HelveticaBold).map_err(|e| e.to_string())?;
        let mono = doc.add_builtin_font(BuiltinFont::Courier).map_err(|e| e.to_string())?;
        let layer = doc.get_page(page).get_layer(layer_idx);
        Ok(Pdf { doc, font, bold, mono, layer, y: TOP })
    }

    fn new_page(&mut self) {
        let (page, layer_idx) = self.doc.add_page(Mm(PAGE_W as f32), Mm(PAGE_H as f32), "Capa");
        self.layer = self.doc.get_page(page).get_layer(layer_idx);
        self.y = TOP;
    }

    fn ensure(&mut self, needed: f64) {
        if self.y - needed < BOTTOM {
            self.new_page();
        }
    }

    fn text(&mut self, s: &str, size: f64, bold: bool, indent: f64) {
        let font = if bold { self.bold.clone() } else { self.font.clone() };
        let max = MAX_CHARS.saturating_sub((indent * 0.5) as usize).max(20);
        for line in wrap(s, max) {
            self.ensure(LINE_H);
            self.layer.use_text(line.as_str(), size as f32, Mm((MARGIN + indent) as f32), Mm(self.y as f32), &font);
            self.y -= LINE_H;
        }
    }

    fn code(&mut self, s: &str, indent: f64) {
        for line in wrap(s, MAX_CHARS + 8) {
            self.ensure(4.4);
            self.layer.use_text(line.as_str(), 8.0, Mm((MARGIN + indent) as f32), Mm(self.y as f32), &self.mono);
            self.y -= 4.4;
        }
    }

    fn gap(&mut self, mm: f64) {
        self.y -= mm;
    }

    fn into_bytes(self) -> Result<Vec<u8>, String> {
        self.doc
            .save_to_bytes()
            .map_err(|e| format!("Error al generar el PDF: {e}"))
    }
}

pub fn generate(report: &AuditReport) -> Result<Vec<u8>, String> {
    let mut p = Pdf::new()?;

    p.text("VibeAuditt — Informe de seguridad", 18.0, true, 0.0);
    p.gap(2.0);
    p.text(&report.url, 11.0, true, 0.0);
    p.text(
        &format!(
            "{}  ·  modo {}  ·  {} checks  ·  {} ms",
            format_date(&report.created_at),
            mode_label(report.mode),
            report.checks_run,
            report.duration_ms
        ),
        9.0,
        false,
        0.0,
    );
    p.gap(3.0);
    p.text(&format!("Puntuacion: {}/100    Nota: {}", report.score, report.grade), 13.0, true, 0.0);
    let c = &report.counts;
    p.text(
        &format!(
            "Critico {}   Alto {}   Medio {}   Bajo {}   Info {}",
            c.critical, c.high, c.medium, c.low, c.info
        ),
        10.0,
        false,
        0.0,
    );
    p.gap(4.0);
    p.text("Hallazgos", 14.0, true, 0.0);
    p.gap(2.0);

    let issues: Vec<&Finding> = report.findings.iter().filter(|f| f.severity != Severity::Clean).collect();
    if issues.is_empty() {
        p.text("No se detectaron vulnerabilidades en esta auditoria.", 10.0, false, 0.0);
    }

    for f in issues {
        p.ensure(24.0);
        let tag = if f.confidence == Confidence::Confirmed { " (Explotable)" } else { "" };
        p.text(&format!("[{}] {}{}", sev_label(f.severity), f.title, tag), 11.0, true, 0.0);
        p.text(&format!("Categoria: {}  ·  id: {}", f.category, f.id), 8.5, false, 2.0);
        if !f.summary.is_empty() {
            p.text(&f.summary, 9.5, false, 2.0);
        }
        if !f.evidence.is_empty() {
            p.text("Evidencia:", 8.5, true, 2.0);
            for e in &f.evidence {
                p.code(e, 4.0);
            }
        }
        if let Some(poc) = &f.poc {
            p.text("Prueba de concepto:", 8.5, true, 2.0);
            p.text(poc, 9.0, false, 4.0);
        }
        if !f.attack_chain.is_empty() {
            p.text("Como te explotaria un atacante:", 8.5, true, 2.0);
            for (i, step) in f.attack_chain.iter().enumerate() {
                p.text(&format!("{}. {}", i + 1, step), 9.0, false, 4.0);
            }
        }
        if !f.remediation.is_empty() {
            p.text("Mitigacion:", 8.5, true, 2.0);
            p.text(&f.remediation, 9.0, false, 4.0);
        }
        if !f.references.is_empty() {
            p.text(&format!("Referencias: {}", f.references.join("  ·  ")), 8.0, false, 2.0);
        }
        p.gap(4.0);
    }

    p.into_bytes()
}

fn wrap(s: &str, max: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for raw in s.split('\n') {
        let mut cur = String::new();
        for word in raw.split(' ') {
            if !cur.is_empty() && cur.chars().count() + word.chars().count() + 1 > max {
                lines.push(std::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
            while cur.chars().count() > max {
                let chunk: String = cur.chars().take(max).collect();
                lines.push(chunk);
                cur = cur.chars().skip(max).collect();
            }
        }
        lines.push(cur);
    }
    lines
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICO",
        Severity::High => "ALTO",
        Severity::Medium => "MEDIO",
        Severity::Low => "BAJO",
        Severity::Info => "INFO",
        Severity::Clean => "OK",
    }
}

fn mode_label(m: AuditMode) -> &'static str {
    match m {
        AuditMode::Passive => "Pasivo",
        AuditMode::Active => "Activo",
        AuditMode::Deep => "Pentest profundo",
    }
}

fn format_date(iso: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|d| d.format("%d/%m/%Y %H:%M").to_string())
        .unwrap_or_else(|_| iso.to_string())
}
