use std::path::Path;

use rusqlite::{params, Connection};

use crate::engine::ruleset::Ruleset;
use crate::engine::types::{AuditReport, AuditSummary, SeverityCounts};

/// Almacén local SQLite del histórico de auditorías.
pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audits (
                id          TEXT PRIMARY KEY,
                url         TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                score       INTEGER NOT NULL,
                grade       TEXT NOT NULL,
                critical    INTEGER NOT NULL,
                high        INTEGER NOT NULL,
                medium      INTEGER NOT NULL,
                low         INTEGER NOT NULL,
                info        INTEGER NOT NULL,
                report_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS catalog (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                json        TEXT NOT NULL,
                version     TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Db { conn })
    }

    pub fn save_catalog(&self, r: &Ruleset, updated_at: &str) -> Result<(), String> {
        let json = serde_json::to_string(r).map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO catalog (id, json, version, updated_at)
                 VALUES (1, ?1, ?2, ?3)",
                params![json, r.version, updated_at],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_catalog(&self) -> Option<Ruleset> {
        let json: String = self
            .conn
            .query_row("SELECT json FROM catalog WHERE id = 1", [], |row| row.get(0))
            .ok()?;
        serde_json::from_str(&json).ok()
    }

    pub fn catalog_updated_at(&self) -> Option<String> {
        self.conn
            .query_row("SELECT updated_at FROM catalog WHERE id = 1", [], |row| {
                row.get(0)
            })
            .ok()
    }

    pub fn save(&self, r: &AuditReport) -> Result<(), String> {
        let json = serde_json::to_string(r).map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO audits
                 (id, url, created_at, score, grade, critical, high, medium, low, info, report_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    r.id,
                    r.url,
                    r.created_at,
                    r.score,
                    r.grade,
                    r.counts.critical,
                    r.counts.high,
                    r.counts.medium,
                    r.counts.low,
                    r.counts.info,
                    json,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<AuditSummary>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, url, created_at, score, grade, critical, high, medium, low, info
                 FROM audits ORDER BY created_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AuditSummary {
                    id: row.get(0)?,
                    url: row.get(1)?,
                    created_at: row.get(2)?,
                    score: row.get::<_, i64>(3)? as u8,
                    grade: row.get(4)?,
                    counts: SeverityCounts {
                        critical: row.get::<_, i64>(5)? as u32,
                        high: row.get::<_, i64>(6)? as u32,
                        medium: row.get::<_, i64>(7)? as u32,
                        low: row.get::<_, i64>(8)? as u32,
                        info: row.get::<_, i64>(9)? as u32,
                    },
                })
            })
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Result<AuditReport, String> {
        let json: String = self
            .conn
            .query_row("SELECT report_json FROM audits WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM audits WHERE id = ?1", [id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
