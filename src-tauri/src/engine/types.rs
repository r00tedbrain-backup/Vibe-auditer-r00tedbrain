use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Clean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Fail,
    Warn,
    Pass,
    Info,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Detected,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    Passive,
    Active,
    Deep,
}

impl AuditMode {
    /// Activo o profundo: habilita los PoC de lectura mínima.
    pub fn is_active(self) -> bool {
        matches!(self, AuditMode::Active | AuditMode::Deep)
    }
    /// Solo el modo profundo (pentest): enumeración ampliada, CVEs, muestreo.
    pub fn is_deep(self) -> bool {
        matches!(self, AuditMode::Deep)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub check_id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub confidence: Confidence,
    pub summary: String,
    pub evidence: Vec<String>,
    pub poc: Option<String>,
    pub remediation: String,
    pub prompt: String,
    pub references: Vec<String>,
    /// Pasos narrados de cómo un atacante encadenaría esta vulnerabilidad.
    pub attack_chain: Vec<String>,
}

impl Finding {
    /// Crea un hallazgo (status Fail, confianza Detected por defecto).
    pub fn new(
        check_id: &str,
        version: u32,
        title: &str,
        category: &str,
        severity: Severity,
    ) -> Self {
        Finding {
            id: format!("{check_id}.v{version}"),
            check_id: check_id.to_string(),
            title: title.to_string(),
            category: category.to_string(),
            severity,
            status: FindingStatus::Fail,
            confidence: Confidence::Detected,
            summary: String::new(),
            evidence: Vec::new(),
            poc: None,
            remediation: String::new(),
            prompt: String::new(),
            references: Vec::new(),
            attack_chain: Vec::new(),
        }
    }

    /// Hallazgo "correcto" (check superado).
    pub fn pass(check_id: &str, version: u32, title: &str, category: &str) -> Self {
        let mut f = Finding::new(check_id, version, title, category, Severity::Clean);
        f.status = FindingStatus::Pass;
        f
    }

    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }
    pub fn add_evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
    pub fn evidence(mut self, e: Vec<String>) -> Self {
        self.evidence = e;
        self
    }
    /// Marca el hallazgo como confirmado con un PoC no destructivo.
    pub fn poc(mut self, p: impl Into<String>) -> Self {
        self.poc = Some(p.into());
        self.confidence = Confidence::Confirmed;
        self
    }
    pub fn remediation(mut self, r: impl Into<String>) -> Self {
        self.remediation = r.into();
        self
    }
    pub fn prompt(mut self, p: impl Into<String>) -> Self {
        self.prompt = p.into();
        self
    }
    pub fn refs(mut self, r: &[&str]) -> Self {
        self.references = r.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn attack_chain(mut self, steps: &[&str]) -> Self {
        self.attack_chain = steps.iter().map(|s| s.to_string()).collect();
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub id: String,
    pub url: String,
    pub final_url: String,
    pub mode: AuditMode,
    pub created_at: String,
    pub duration_ms: u64,
    pub score: u8,
    pub grade: String,
    pub counts: SeverityCounts,
    pub findings: Vec<Finding>,
    pub checks_run: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSummary {
    pub id: String,
    pub url: String,
    pub created_at: String,
    pub score: u8,
    pub grade: String,
    pub counts: SeverityCounts,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub audit_id: String,
    pub done: u32,
    pub total: u32,
    pub current: String,
}
