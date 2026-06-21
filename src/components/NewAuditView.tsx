import { useState, type ReactNode } from "react";
import {
  AlertTriangle,
  Crosshair,
  Database,
  Globe,
  Loader2,
  ScanSearch,
  Zap,
} from "lucide-react";
import type { AuditMode, ProgressEvent } from "../lib/types";

function isValidHttpUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function hostOf(s: string): string {
  try {
    return new URL(s).host;
  } catch {
    return s;
  }
}

type Target = "web" | "db";

export function NewAuditView({
  running,
  progress,
  error,
  onRun,
  onRunDb,
}: {
  running: boolean;
  progress: ProgressEvent | null;
  error: string | null;
  onRun: (url: string, mode: AuditMode, consent: boolean) => void;
  onRunDb: (connection: string, consent: boolean) => void;
}) {
  const [target, setTarget] = useState<Target>("web");
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState<AuditMode>("passive");
  const [consent, setConsent] = useState(false);
  const [conn, setConn] = useState("");
  const [showDeepModal, setShowDeepModal] = useState(false);

  const trimmed = url.trim();
  const valid = isValidHttpUrl(trimmed);
  const canRunWeb = valid && consent && !running;
  const canRunDb = conn.trim().length > 10 && consent && !running;

  function submitWeb() {
    if (!canRunWeb) return;
    if (mode === "deep") {
      setShowDeepModal(true);
      return;
    }
    onRun(trimmed, mode, consent);
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-10 va-fade-in">
      <h1
        className="text-3xl font-semibold tracking-tight"
        style={{ color: "var(--text-primary)" }}
      >
        Nueva auditoría
      </h1>
      <p className="mt-2 text-lg" style={{ color: "var(--text-secondary)" }}>
        Analiza tu SaaS hecho con IA: la aplicación web o, con credenciales, tu
        base de datos.
      </p>

      {/* Selector de objetivo */}
      <div className="mt-6 grid grid-cols-2 gap-3">
        <TargetCard
          active={target === "web"}
          disabled={running}
          onClick={() => setTarget("web")}
          icon={<Globe className="h-5 w-5" />}
          title="Aplicación web"
          desc="Audita una URL pública (headers, secretos, inyección, subdominios…)."
        />
        <TargetCard
          active={target === "db"}
          disabled={running}
          onClick={() => setTarget("db")}
          icon={<Database className="h-5 w-5" />}
          title="Base de datos"
          desc="Conecta a tu PostgreSQL/Supabase y audita RLS, roles, permisos y SSL."
        />
      </div>

      {target === "web" ? (
        <div className="mt-6 space-y-5">
          <div>
            <label
              htmlFor="audit-url"
              className="mb-1.5 block text-sm font-medium"
              style={{ color: "var(--text-primary)" }}
            >
              URL del SaaS a auditar
            </label>
            <input
              id="audit-url"
              type="url"
              inputMode="url"
              autoComplete="url"
              placeholder="https://tu-saas.com"
              value={url}
              onChange={(e) => setUrl(e.currentTarget.value)}
              disabled={running}
              onKeyDown={(e) => {
                if (e.key === "Enter") submitWeb();
              }}
              className="h-12 w-full rounded-md border bg-transparent px-4 text-base outline-none transition-colors placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] disabled:opacity-60"
              style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}
            />
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <ModeCard
              active={mode === "passive"}
              disabled={running}
              onClick={() => setMode("passive")}
              icon={<ScanSearch className="h-5 w-5" />}
              title="Pasivo"
              desc="Solo lectura: HTML, bundles y headers. No toca el backend."
            />
            <ModeCard
              active={mode === "active"}
              disabled={running}
              onClick={() => setMode("active")}
              icon={<Zap className="h-5 w-5" />}
              title="Activo (PoC)"
              desc="Pasivo + pruebas no destructivas: lee 1 muestra y canaries inertes."
            />
            <ModeCard
              active={mode === "deep"}
              disabled={running}
              onClick={() => setMode("deep")}
              icon={<Crosshair className="h-5 w-5" />}
              title="Pentest profundo"
              desc="CVEs, subdominios, inyección y cadena de ataque, sin romper nada."
              danger
            />
          </div>

          {(mode === "active" || mode === "deep") && (
            <div
              className="flex gap-2 rounded-lg border p-3 text-sm"
              style={{
                borderColor: mode === "deep" ? "var(--sev-critical-border)" : "var(--sev-high-border)",
                backgroundColor: mode === "deep" ? "var(--sev-critical-bg)" : "var(--sev-high-bg)",
                color: "var(--text-primary)",
              }}
            >
              <AlertTriangle
                className="mt-0.5 h-4 w-4 shrink-0"
                style={{ color: mode === "deep" ? "var(--sev-critical)" : "var(--sev-high)" }}
              />
              <span>
                {mode === "deep"
                  ? "El modo profundo enumera tu superficie como un atacante real (solo lectura, nunca escribe). Genera bastante tráfico; úsalo solo en aplicaciones de tu propiedad."
                  : "El modo activo envía peticiones de prueba (solo lectura, nunca escribe ni borra). Úsalo únicamente en aplicaciones de tu propiedad."}
              </span>
            </div>
          )}

          <ConsentBox consent={consent} setConsent={setConsent} running={running} kind="esta aplicación" />

          <button
            type="button"
            disabled={!canRunWeb}
            onClick={submitWeb}
            className="inline-flex h-12 items-center justify-center gap-2 rounded-md px-6 text-base font-medium transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            style={{ backgroundColor: "var(--accent-primary)", color: "var(--accent-primary-fg)" }}
          >
            {running ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" /> Auditando…
              </>
            ) : mode === "deep" ? (
              "Lanzar pentest"
            ) : (
              "Auditar"
            )}
          </button>
        </div>
      ) : (
        <div className="mt-6 space-y-5">
          <div>
            <label
              htmlFor="db-conn"
              className="mb-1.5 block text-sm font-medium"
              style={{ color: "var(--text-primary)" }}
            >
              Cadena de conexión PostgreSQL
            </label>
            <textarea
              id="db-conn"
              rows={2}
              placeholder="postgresql://usuario:contraseña@host:5432/basededatos"
              value={conn}
              onChange={(e) => setConn(e.currentTarget.value)}
              disabled={running}
              spellCheck={false}
              className="w-full rounded-md border bg-transparent px-4 py-3 font-mono text-sm outline-none transition-colors placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] disabled:opacity-60"
              style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}
            />
            <p className="mt-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
              Funciona con Supabase (cadena de conexión del proyecto). La cadena
              <strong> no se guarda</strong>: solo se usa para esta auditoría. Usa un
              usuario de solo lectura si puedes.
            </p>
          </div>

          <ConsentBox consent={consent} setConsent={setConsent} running={running} kind="esta base de datos" />

          <button
            type="button"
            disabled={!canRunDb}
            onClick={() => canRunDb && onRunDb(conn.trim(), consent)}
            className="inline-flex h-12 items-center justify-center gap-2 rounded-md px-6 text-base font-medium transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            style={{ backgroundColor: "var(--accent-primary)", color: "var(--accent-primary-fg)" }}
          >
            {running ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" /> Auditando base de datos…
              </>
            ) : (
              "Auditar base de datos"
            )}
          </button>
        </div>
      )}

      {error && (
        <p className="mt-4 text-sm" style={{ color: "var(--sev-critical)" }}>
          {error}
        </p>
      )}

      {running && progress && progress.total > 0 && (
        <div
          className="mt-8 rounded-xl border p-5"
          style={{ borderColor: "var(--border-subtle)", backgroundColor: "var(--bg-surface)" }}
        >
          <div className="mb-2 flex items-center justify-between text-sm">
            <span style={{ color: "var(--text-secondary)" }}>{progress.current}</span>
            <span className="font-mono tabular-nums" style={{ color: "var(--text-muted)" }}>
              {progress.done}/{progress.total}
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full" style={{ backgroundColor: "var(--bg-elevated)" }}>
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: `${Math.round((progress.done / progress.total) * 100)}%`,
                backgroundColor: "var(--accent-primary)",
              }}
            />
          </div>
        </div>
      )}

      {showDeepModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: "var(--bg-overlay)" }}
          onClick={() => setShowDeepModal(false)}
        >
          <div
            className="w-full max-w-lg rounded-xl border p-6 va-fade-in"
            style={{ borderColor: "var(--sev-critical-border)", backgroundColor: "var(--bg-surface)" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2">
              <Crosshair className="h-5 w-5" style={{ color: "var(--sev-critical)" }} />
              <h3 className="text-lg font-semibold" style={{ color: "var(--text-primary)" }}>
                Modo Pentest profundo
              </h3>
            </div>
            <p className="mt-3 text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
              Vas a lanzar un análisis tipo atacante real contra{" "}
              <strong style={{ color: "var(--text-primary)" }}>{hostOf(trimmed)}</strong>:
              enumeración de superficie, CVEs e inyección no destructiva. Solo lectura, pero
              genera tráfico que puede disparar tu WAF o rate-limits. Úsalo solo en sistemas
              de tu propiedad.
            </p>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowDeepModal(false)}
                className="rounded-md border px-4 py-2 text-sm transition-colors hover:bg-[var(--bg-elevated)]"
                style={{ borderColor: "var(--border-default)", color: "var(--text-primary)" }}
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowDeepModal(false);
                  onRun(trimmed, "deep", consent);
                }}
                className="rounded-md px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
                style={{ backgroundColor: "var(--sev-critical)" }}
              >
                Entiendo, lanzar pentest
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ConsentBox({
  consent,
  setConsent,
  running,
  kind,
}: {
  consent: boolean;
  setConsent: (v: boolean) => void;
  running: boolean;
  kind: string;
}) {
  return (
    <label
      className="flex cursor-pointer items-start gap-2.5 text-sm"
      style={{ color: "var(--text-secondary)" }}
    >
      <input
        type="checkbox"
        checked={consent}
        disabled={running}
        onChange={(e) => setConsent(e.currentTarget.checked)}
        className="mt-0.5 h-5 w-5 shrink-0"
        style={{ accentColor: "var(--accent-primary)" }}
      />
      <span>
        Confirmo que soy propietario de {kind} o tengo autorización por escrito para
        auditarla.
      </span>
    </label>
  );
}

function TargetCard(props: {
  active: boolean;
  disabled?: boolean;
  onClick: () => void;
  icon: ReactNode;
  title: string;
  desc: string;
}) {
  return <ModeCard {...props} />;
}

function ModeCard({
  active,
  disabled,
  onClick,
  icon,
  title,
  desc,
  danger,
}: {
  active: boolean;
  disabled?: boolean;
  onClick: () => void;
  icon: ReactNode;
  title: string;
  desc: string;
  danger?: boolean;
}) {
  const activeBorder = danger ? "var(--sev-critical)" : "var(--accent-primary)";
  const activeBg = danger ? "var(--sev-critical-bg)" : "var(--sev-clean-bg)";
  const activeIcon = danger ? "var(--sev-critical)" : "var(--accent-text)";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-xl border p-4 text-left transition-colors disabled:opacity-60"
      style={{
        borderColor: active ? activeBorder : "var(--border-subtle)",
        backgroundColor: active ? activeBg : "var(--bg-surface)",
      }}
    >
      <div className="flex items-center gap-2">
        <span style={{ color: active ? activeIcon : "var(--text-secondary)" }}>{icon}</span>
        <span className="font-semibold" style={{ color: "var(--text-primary)" }}>
          {title}
        </span>
      </div>
      <p className="mt-1.5 text-sm leading-relaxed" style={{ color: "var(--text-secondary)" }}>
        {desc}
      </p>
    </button>
  );
}
