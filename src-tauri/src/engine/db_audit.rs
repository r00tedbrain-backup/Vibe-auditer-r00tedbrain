use std::time::Instant;

use chrono::Utc;
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use tokio_postgres::{Client, Row};
use url::Url;
use uuid::Uuid;

use crate::engine::score::{counts_from, grade_from, score_from_findings};
use crate::engine::types::{AuditMode, AuditReport, Finding, Severity};

const CAT_DB: &str = "Base de datos";

/// Conecta a una base de datos PostgreSQL y audita su configuración real.
pub async fn audit_database(conn: &str) -> Result<AuditReport, String> {
    let started = Instant::now();

    let tls = TlsConnector::builder()
        .build()
        .map_err(|e| format!("No se pudo inicializar TLS: {e}"))?;
    let connector = MakeTlsConnector::new(tls);

    let (client, connection) = tokio_postgres::connect(conn, connector)
        .await
        .map_err(|e| format!("No se pudo conectar a la base de datos: {e}"))?;
    let conn_handle = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut findings = Vec::new();
    findings.extend(check_rls(&client).await);
    findings.extend(check_roles(&client).await);
    findings.extend(check_public_grants(&client).await);
    findings.extend(check_extensions(&client).await);
    findings.extend(check_sensitive_columns(&client).await);
    findings.extend(check_settings(&client).await);
    findings.extend(check_version(&client).await);

    conn_handle.abort();

    if findings.iter().all(|f| f.severity == Severity::Clean || f.severity == Severity::Info) {
        findings.push(
            Finding::pass("db_audit", 1, "Configuración de base de datos correcta", CAT_DB)
                .summary("No se detectaron problemas graves de configuración (RLS, roles, permisos, SSL)."),
        );
    }

    let counts = counts_from(&findings);
    let score = score_from_findings(&findings);
    let grade = grade_from(score);
    findings.sort_by_key(|f| sev_rank(f.severity));

    Ok(AuditReport {
        id: Uuid::new_v4().to_string(),
        url: censor(conn),
        final_url: censor(conn),
        mode: AuditMode::Deep,
        created_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        score,
        grade,
        counts,
        checks_run: 7,
        findings,
    })
}

async fn q(client: &Client, sql: &str) -> Vec<Row> {
    client.query(sql, &[]).await.unwrap_or_default()
}

async fn check_rls(client: &Client) -> Vec<Finding> {
    let rows = q(
        client,
        "SELECT n.nspname::text, c.relname::text FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind = 'r' AND NOT c.relrowsecurity \
         AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast') ORDER BY 1,2",
    )
    .await;
    if rows.is_empty() {
        return Vec::new();
    }
    let tables: Vec<String> = rows
        .iter()
        .take(30)
        .map(|r| format!("{}.{}", r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect();
    vec![Finding::new("db_rls", 1, "Tablas sin Row Level Security", CAT_DB, Severity::High)
        .summary(format!(
            "{} tabla(s) no tienen RLS habilitado. Crítico si la base de datos es accesible \
             directamente (Supabase/PostgREST); menor si solo accede tu backend.",
            rows.len()
        ))
        .evidence(tables)
        .attack_chain(&[
            "Consigo la anon key pública o una conexión directa a la base de datos.",
            "Leo las tablas sin RLS sin restricción por fila.",
            "Accedo a los datos de todos los usuarios.",
        ])
        .remediation(
            "Habilita RLS (ALTER TABLE ... ENABLE ROW LEVEL SECURITY) y crea políticas por \
             propietario en las tablas accesibles desde el cliente.",
        )
        .prompt(
            "Tengo tablas sin RLS en Postgres. Genera el SQL para habilitar RLS y políticas por \
             usuario en las tablas accesibles desde el cliente.",
        )
        .refs(&["Supabase RLS", "CWE-284: Improper Access Control"])]
}

async fn check_roles(client: &Client) -> Vec<Finding> {
    let rows = q(
        client,
        "SELECT rolname::text, rolsuper, rolbypassrls FROM pg_roles \
         WHERE rolcanlogin AND (rolsuper OR rolbypassrls) ORDER BY 1",
    )
    .await;
    if rows.is_empty() {
        return Vec::new();
    }
    let ev: Vec<String> = rows
        .iter()
        .map(|r| {
            let name: String = r.get(0);
            let sup: bool = r.get(1);
            let bypass: bool = r.get(2);
            let mut tags = Vec::new();
            if sup {
                tags.push("SUPERUSER");
            }
            if bypass {
                tags.push("BYPASSRLS");
            }
            format!("{name}: {}", tags.join(", "))
        })
        .collect();
    vec![Finding::new("db_roles", 1, "Roles con privilegios excesivos", CAT_DB, Severity::Medium)
        .summary(
            "Hay roles con login que son SUPERUSER o pueden saltarse RLS. Si se comprometen sus \
             credenciales, el atacante obtiene control total.",
        )
        .evidence(ev)
        .remediation(
            "Usa un rol de mínimos privilegios para la aplicación; reserva SUPERUSER solo para \
             administración puntual.",
        )
        .prompt(
            "Tengo roles de DB con SUPERUSER/BYPASSRLS usados por la app. Dime cómo crear un rol \
             de mínimos privilegios para la aplicación.",
        )]
}

async fn check_public_grants(client: &Client) -> Vec<Finding> {
    let rows = q(
        client,
        "SELECT table_schema::text, table_name::text, string_agg(DISTINCT privilege_type, ',')::text \
         FROM information_schema.role_table_grants \
         WHERE grantee = 'PUBLIC' AND table_schema NOT IN ('pg_catalog','information_schema') \
         GROUP BY 1,2 ORDER BY 1,2",
    )
    .await;
    if rows.is_empty() {
        return Vec::new();
    }
    let ev: Vec<String> = rows
        .iter()
        .take(30)
        .map(|r| {
            format!(
                "{}.{} → {}",
                r.get::<_, String>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2)
            )
        })
        .collect();
    vec![Finding::new("db_public_grants", 1, "Permisos concedidos a PUBLIC", CAT_DB, Severity::High)
        .summary(
            "Hay tablas con permisos concedidos al rol PUBLIC: cualquier rol con conexión puede \
             acceder a ellas.",
        )
        .evidence(ev)
        .remediation(
            "Revoca los permisos de PUBLIC (REVOKE ... FROM PUBLIC) y concede solo a los roles \
             necesarios.",
        )
        .prompt(
            "Tengo tablas con grants a PUBLIC en Postgres. Genera el SQL para revocarlos y conceder \
             solo a los roles de mi app.",
        )]
}

async fn check_extensions(client: &Client) -> Vec<Finding> {
    let rows = q(client, "SELECT extname::text FROM pg_extension").await;
    let dangerous: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let n: String = r.get(0);
            if ["dblink", "file_fdw", "postgres_fdw", "plpythonu", "plperlu", "adminpack"]
                .contains(&n.as_str())
            {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    if dangerous.is_empty() {
        return Vec::new();
    }
    vec![Finding::new("db_extensions", 1, "Extensiones potencialmente peligrosas", CAT_DB, Severity::Medium)
        .summary(
            "Hay extensiones instaladas que amplían la superficie (acceso a ficheros, red o \
             ejecución de código).",
        )
        .evidence(dangerous)
        .remediation("Elimina las extensiones que no uses (DROP EXTENSION) y limita quién puede usarlas.")
        .prompt("Tengo extensiones como dblink/file_fdw en Postgres. Dime cuáles puedo eliminar de forma segura.")]
}

async fn check_sensitive_columns(client: &Client) -> Vec<Finding> {
    let rows = q(
        client,
        "SELECT table_schema::text, table_name::text, column_name::text FROM information_schema.columns \
         WHERE table_schema NOT IN ('pg_catalog','information_schema') \
         AND (column_name ILIKE '%password%' OR column_name ILIKE '%passwd%' \
              OR column_name ILIKE '%secret%' OR column_name ILIKE '%token%' \
              OR column_name ILIKE '%ssn%') ORDER BY 1,2,3",
    )
    .await;
    if rows.is_empty() {
        return Vec::new();
    }
    let ev: Vec<String> = rows
        .iter()
        .take(30)
        .map(|r| {
            format!(
                "{}.{}.{}",
                r.get::<_, String>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2)
            )
        })
        .collect();
    vec![Finding::new("db_sensitive_columns", 1, "Columnas con datos sensibles", CAT_DB, Severity::Info)
        .summary(
            "Se detectaron columnas que parecen contener datos sensibles. Verifica que las \
             contraseñas estén hasheadas (bcrypt/argon2) y los secretos cifrados en reposo.",
        )
        .evidence(ev)
        .remediation(
            "Hashea contraseñas con bcrypt/argon2 (nunca texto plano ni MD5/SHA1). Cifra \
             tokens/secretos en reposo.",
        )
        .prompt(
            "Tengo columnas de password/token en mi DB. Dime cómo asegurarme de que están \
             correctamente hasheadas/cifradas.",
        )]
}

async fn check_settings(client: &Client) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(row) = q(client, "SHOW ssl").await.first() {
        let ssl: String = row.get(0);
        if ssl != "on" {
            out.push(
                Finding::new("db_ssl", 1, "Conexiones sin SSL", CAT_DB, Severity::Medium)
                    .summary("El servidor no fuerza SSL: las conexiones pueden viajar sin cifrar.")
                    .add_evidence(format!("ssl = {ssl}"))
                    .remediation("Habilita y exige SSL (ssl = on, y sslmode=require en los clientes).")
                    .prompt("Mi Postgres no fuerza SSL. Dime cómo habilitarlo y exigirlo."),
            );
        }
    }
    if let Some(row) = q(client, "SHOW password_encryption").await.first() {
        let pe: String = row.get(0);
        if pe.to_lowercase().contains("md5") {
            out.push(
                Finding::new("db_password_enc", 1, "Cifrado de contraseñas débil (md5)", CAT_DB, Severity::Medium)
                    .summary("Postgres usa md5 para las contraseñas de roles; scram-sha-256 es mucho más seguro.")
                    .add_evidence(format!("password_encryption = {pe}"))
                    .remediation("Cambia a password_encryption = scram-sha-256 y re-establece las contraseñas de los roles.")
                    .prompt("Mi Postgres usa md5 para password_encryption. Dime cómo migrar a scram-sha-256."),
            );
        }
    }
    out
}

async fn check_version(client: &Client) -> Vec<Finding> {
    let rows = q(client, "SHOW server_version").await;
    if let Some(row) = rows.first() {
        let v: String = row.get(0);
        return vec![Finding::new("db_version", 1, "Versión de PostgreSQL", CAT_DB, Severity::Info)
            .summary(format!(
                "PostgreSQL {v}. Mantén el servidor con los últimos parches menores de seguridad."
            ))
            .add_evidence(format!("server_version = {v}"))
            .remediation("Aplica las actualizaciones menores de PostgreSQL con regularidad.")
            .prompt(format!(
                "Uso PostgreSQL {v}. Dime si tiene vulnerabilidades conocidas y a qué versión menor actualizar."
            ))];
    }
    Vec::new()
}

fn censor(conn: &str) -> String {
    if let Ok(u) = Url::parse(conn) {
        let user = u.username();
        let host = u.host_str().unwrap_or("?");
        let db = u.path().trim_start_matches('/');
        let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
        return format!("postgresql://{user}@{host}{port}/{db}");
    }
    "base de datos".to_string()
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
