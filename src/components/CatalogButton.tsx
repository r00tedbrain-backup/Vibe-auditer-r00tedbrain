import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { getCatalogInfo, updateCatalog, type CatalogInfo } from "../lib/catalog";

export function CatalogButton() {
  const [info, setInfo] = useState<CatalogInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    getCatalogInfo()
      .then(setInfo)
      .catch(() => {});
  }, []);

  async function update() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await updateCatalog();
      const added = r.addedSecretRules + r.addedKev;
      setMsg(
        added > 0
          ? `+${r.addedSecretRules} reglas · +${r.addedKev} CVEs`
          : "Ya estaba al día",
      );
      setInfo({
        totalSecretRules: r.totalSecretRules,
        totalKev: r.totalKev,
        version: r.version,
        updatedAt: r.updatedAt,
      });
    } catch {
      setMsg("Error al actualizar");
    } finally {
      setBusy(false);
      window.setTimeout(() => setMsg(null), 5000);
    }
  }

  return (
    <div className="px-3 pb-1">
      <button
        type="button"
        onClick={update}
        disabled={busy}
        className="inline-flex w-full items-center justify-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-[var(--bg-elevated)] disabled:opacity-60"
        style={{ borderColor: "var(--border-default)", color: "var(--text-secondary)" }}
      >
        <RefreshCw className={"h-4 w-4 " + (busy ? "animate-spin" : "")} />
        {busy ? "Actualizando…" : "Actualizar catálogo"}
      </button>
      <p
        className="mt-1.5 px-1 text-center text-xs"
        style={{ color: msg ? "var(--accent-text)" : "var(--text-muted)" }}
      >
        {msg ??
          (info
            ? `${info.totalSecretRules} reglas · ${info.totalKev} CVEs`
            : "Catálogo base")}
      </p>
    </div>
  );
}
