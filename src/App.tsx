import { useCallback, useEffect, useState } from "react";
import type {
  AuditMode,
  AuditReport,
  AuditSummary,
  ProgressEvent,
} from "./lib/types";
import {
  auditDatabase,
  deleteAudit,
  getAudit,
  listAudits,
  onAuditProgress,
  runAudit,
  scanApi,
} from "./lib/audit";
import { Sidebar } from "./components/Sidebar";
import { NewAuditView } from "./components/NewAuditView";
import { ReportView } from "./components/ReportView";

type View = "new" | "report";

function App() {
  const [view, setView] = useState<View>("new");
  const [audits, setAudits] = useState<AuditSummary[]>([]);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setAudits(await listAudits());
    } catch {
      /* base aún vacía o sin permisos: ignoramos en v1 */
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Suscripción al progreso emitido por el motor.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    onAuditProgress(setProgress).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, []);

  const handleRun = useCallback(
    async (url: string, mode: AuditMode, consent: boolean) => {
      setError(null);
      setRunning(true);
      setProgress({ auditId: "", done: 0, total: 1, current: "Iniciando…" });
      try {
        const r = await runAudit(url, mode, consent);
        setReport(r);
        setView("report");
        await refresh();
      } catch (e) {
        setError(typeof e === "string" ? e : "No se pudo completar la auditoría.");
      } finally {
        setRunning(false);
        setProgress(null);
      }
    },
    [refresh],
  );

  const handleRunDb = useCallback(
    async (connection: string, consent: boolean) => {
      setError(null);
      setRunning(true);
      setProgress(null);
      try {
        const r = await auditDatabase(connection, consent);
        setReport(r);
        setView("report");
        await refresh();
      } catch (e) {
        setError(
          typeof e === "string" ? e : "No se pudo auditar la base de datos.",
        );
      } finally {
        setRunning(false);
      }
    },
    [refresh],
  );

  const handleRunApi = useCallback(
    async (base: string, consent: boolean) => {
      setError(null);
      setRunning(true);
      setProgress(null);
      try {
        const r = await scanApi(base, consent);
        setReport(r);
        setView("report");
        await refresh();
      } catch (e) {
        setError(typeof e === "string" ? e : "No se pudo escanear la API.");
      } finally {
        setRunning(false);
      }
    },
    [refresh],
  );

  const handleSelect = useCallback(async (id: string) => {
    try {
      const r = await getAudit(id);
      setReport(r);
      setView("report");
    } catch {
      /* noop */
    }
  }, []);

  const handleNew = useCallback(() => {
    setError(null);
    setView("new");
  }, []);

  const handleDelete = useCallback(
    async (id: string) => {
      try {
        await deleteAudit(id);
        if (report?.id === id) {
          setReport(null);
          setView("new");
        }
        await refresh();
      } catch {
        /* noop */
      }
    },
    [report, refresh],
  );

  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <Sidebar
        audits={audits}
        activeId={view === "report" ? report?.id ?? null : null}
        onNew={handleNew}
        onSelect={handleSelect}
      />
      <main
        className="flex-1 overflow-y-auto"
        style={{ backgroundColor: "var(--bg-base)" }}
      >
        {view === "report" && report ? (
          <ReportView report={report} onNew={handleNew} onDelete={handleDelete} />
        ) : (
          <NewAuditView
            running={running}
            progress={progress}
            error={error}
            onRun={handleRun}
            onRunDb={handleRunDb}
            onRunApi={handleRunApi}
          />
        )}
      </main>
    </div>
  );
}

export default App;
