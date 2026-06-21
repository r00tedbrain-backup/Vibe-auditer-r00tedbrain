use super::types::{Confidence, Finding, Severity, SeverityCounts};

/// Cuenta los hallazgos por severidad (ignora los "clean").
pub fn counts_from(findings: &[Finding]) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for f in findings {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
            Severity::Clean => {}
        }
    }
    c
}

/// Puntuación 0-100. Cada hallazgo resta según su severidad; un hallazgo
/// confirmado (explotable) pesa un 50% más que uno solo detectado.
pub fn score_from_findings(findings: &[Finding]) -> u8 {
    let mut penalty = 0f32;
    for f in findings {
        let base: f32 = match f.severity {
            Severity::Critical => 30.0,
            Severity::High => 15.0,
            Severity::Medium => 7.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
            Severity::Clean => 0.0,
        };
        let mult = if f.confidence == Confidence::Confirmed {
            1.5
        } else {
            1.0
        };
        penalty += base * mult;
    }
    (100.0 - penalty).clamp(0.0, 100.0).round() as u8
}

pub fn grade_from(score: u8) -> String {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
    .to_string()
}
