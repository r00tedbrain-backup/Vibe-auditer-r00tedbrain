import {
  Document,
  Page,
  StyleSheet,
  Text,
  View,
  pdf,
} from "@react-pdf/renderer";
import type { AuditReport, Finding, Severity } from "../lib/types";
import { saveReportPdf } from "../lib/catalog";
import { formatDate, formatDuration, hostname } from "../lib/format";

const COL = {
  text: "#18181b",
  sec: "#3f3f46",
  muted: "#71717a",
  border: "#e4e4e7",
  base: "#ffffff",
  accent: "#3f6212",
  crit: "#b91c1c",
  high: "#b45309",
  med: "#a16207",
  low: "#1d4ed8",
  info: "#52525b",
  clean: "#3f6212",
};

const SEV_LABEL: Record<Severity, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  info: "Info",
  clean: "Correcto",
};

function sevColor(s: Severity): string {
  return { critical: COL.crit, high: COL.high, medium: COL.med, low: COL.low, info: COL.info, clean: COL.clean }[s];
}

function gradeColor(grade: string): string {
  const g = (grade || "").toUpperCase().charAt(0);
  if (g === "A") return COL.clean;
  if (g === "B") return COL.low;
  if (g === "C") return COL.med;
  if (g === "D") return COL.high;
  return COL.crit;
}

const MODE_LABEL: Record<string, string> = {
  passive: "Pasivo",
  active: "Activo (PoC)",
  deep: "Pentest profundo",
};

const styles = StyleSheet.create({
  page: {
    paddingTop: 46,
    paddingBottom: 54,
    paddingHorizontal: 44,
    fontSize: 10,
    color: COL.text,
    fontFamily: "Helvetica",
    lineHeight: 1.5,
  },
  brandBar: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 20 },
  brand: { fontSize: 15, fontFamily: "Helvetica-Bold" },
  brandTag: { fontSize: 9, color: COL.muted },
  h1: { fontSize: 20, fontFamily: "Helvetica-Bold", marginBottom: 6 },
  url: { fontSize: 11, color: COL.accent, fontFamily: "Helvetica-Bold", marginBottom: 2 },
  meta: { fontSize: 9, color: COL.muted, marginBottom: 18 },
  scoreRow: { flexDirection: "row", gap: 12, marginBottom: 20 },
  scoreBox: { width: 88, height: 88, borderRadius: 8, borderWidth: 1.5, alignItems: "center", justifyContent: "center" },
  scoreGrade: { fontSize: 34, fontFamily: "Helvetica-Bold" },
  scoreNum: { fontSize: 10, color: COL.muted },
  counts: { flexDirection: "row", flex: 1, gap: 7 },
  countBox: { flex: 1, borderWidth: 1, borderColor: COL.border, borderRadius: 6, paddingVertical: 10, alignItems: "center" },
  countNum: { fontSize: 17, fontFamily: "Helvetica-Bold" },
  countLbl: { fontSize: 8, color: COL.muted, marginTop: 2 },
  sectionTitle: { fontSize: 13, fontFamily: "Helvetica-Bold", marginTop: 12, marginBottom: 8 },
  summaryBox: { borderWidth: 1, borderColor: COL.border, borderRadius: 6, padding: 12, marginBottom: 16, backgroundColor: "#fafafa" },
  card: { borderWidth: 1, borderColor: COL.border, borderRadius: 6, padding: 11, marginBottom: 9 },
  cardHead: { flexDirection: "row", alignItems: "center", marginBottom: 5 },
  sevTag: { fontSize: 8, fontFamily: "Helvetica-Bold", paddingVertical: 2, paddingHorizontal: 5, borderRadius: 3, color: "#ffffff", marginRight: 5 },
  findingTitle: { fontSize: 11, fontFamily: "Helvetica-Bold", flex: 1 },
  fid: { fontSize: 8, color: COL.muted },
  label: { fontSize: 8, fontFamily: "Helvetica-Bold", color: COL.muted, marginTop: 7, marginBottom: 2 },
  body: { fontSize: 9.5, color: COL.sec },
  mono: { fontSize: 8.5, color: COL.sec, fontFamily: "Courier", padding: 5, backgroundColor: "#f4f4f5", borderRadius: 3 },
  chainItem: { fontSize: 9, color: COL.sec, marginBottom: 1 },
  footer: {
    position: "absolute",
    bottom: 26,
    left: 44,
    right: 44,
    flexDirection: "row",
    justifyContent: "space-between",
    fontSize: 8,
    color: COL.muted,
    borderTopWidth: 1,
    borderTopColor: COL.border,
    paddingTop: 6,
  },
});

function FindingBlock({ f }: { f: Finding }) {
  return (
    <View style={styles.card} wrap={false}>
      <View style={styles.cardHead}>
        <Text style={[styles.sevTag, { backgroundColor: sevColor(f.severity) }]}>
          {SEV_LABEL[f.severity]}
        </Text>
        {f.confidence === "confirmed" && (
          <Text style={[styles.sevTag, { backgroundColor: COL.crit }]}>Explotable</Text>
        )}
        <Text style={styles.findingTitle}>{f.title}</Text>
        <Text style={styles.fid}>{f.id}</Text>
      </View>
      <Text style={styles.body}>{f.summary}</Text>

      {f.evidence.length > 0 && (
        <>
          <Text style={styles.label}>EVIDENCIA</Text>
          <Text style={styles.mono}>{f.evidence.join("\n")}</Text>
        </>
      )}
      {f.poc && (
        <>
          <Text style={styles.label}>PRUEBA DE CONCEPTO</Text>
          <Text style={styles.body}>{f.poc}</Text>
        </>
      )}
      {f.attackChain.length > 0 && (
        <>
          <Text style={styles.label}>CADENA DE ATAQUE</Text>
          {f.attackChain.map((s, i) => (
            <Text key={i} style={styles.chainItem}>
              {i + 1}. {s}
            </Text>
          ))}
        </>
      )}
      <Text style={styles.label}>MITIGACIÓN</Text>
      <Text style={styles.body}>{f.remediation}</Text>
      {f.references.length > 0 && (
        <>
          <Text style={styles.label}>REFERENCIAS</Text>
          <Text style={styles.body}>{f.references.join("  ·  ")}</Text>
        </>
      )}
    </View>
  );
}

function ReportDoc({ report }: { report: AuditReport }) {
  const issues = report.findings.filter((f) => f.severity !== "clean");
  const gc = gradeColor(report.grade);
  const c = report.counts;
  const countItems: [Severity, number][] = [
    ["critical", c.critical],
    ["high", c.high],
    ["medium", c.medium],
    ["low", c.low],
    ["info", c.info],
  ];

  return (
    <Document
      title={`Informe VibeAuditt — ${hostname(report.url)}`}
      author="VibeAuditt"
    >
      <Page size="A4" style={styles.page}>
        <View style={styles.brandBar} fixed>
          <Text style={styles.brand}>VibeAuditt</Text>
          <Text style={styles.brandTag}>Informe de seguridad</Text>
        </View>

        <Text style={styles.h1}>Auditoría de seguridad</Text>
        <Text style={styles.url}>{report.url}</Text>
        <Text style={styles.meta}>
          {formatDate(report.createdAt)}  ·  {MODE_LABEL[report.mode] ?? report.mode}  ·{" "}
          {report.checksRun} checks  ·  {formatDuration(report.durationMs)}
        </Text>

        <View style={styles.scoreRow}>
          <View style={[styles.scoreBox, { borderColor: gc }]}>
            <Text style={[styles.scoreGrade, { color: gc }]}>{report.grade}</Text>
            <Text style={styles.scoreNum}>{report.score}/100</Text>
          </View>
          <View style={styles.counts}>
            {countItems.map(([s, n]) => (
              <View key={s} style={styles.countBox}>
                <Text style={[styles.countNum, { color: sevColor(s) }]}>{n}</Text>
                <Text style={styles.countLbl}>{SEV_LABEL[s]}</Text>
              </View>
            ))}
          </View>
        </View>

        <View style={styles.summaryBox}>
          <Text style={styles.body}>
            Se ejecutaron {report.checksRun} comprobaciones de seguridad sobre {report.url} en
            modo {MODE_LABEL[report.mode] ?? report.mode}. Se identificaron {issues.length}{" "}
            hallazgo(s): {c.critical} crítico(s), {c.high} alto(s), {c.medium} medio(s),{" "}
            {c.low} bajo(s) y {c.info} informativo(s). La puntuación global es {report.score}/100
            (nota {report.grade}).
          </Text>
        </View>

        <Text style={styles.sectionTitle}>Hallazgos</Text>
        {issues.length === 0 ? (
          <Text style={styles.body}>No se detectaron vulnerabilidades en esta auditoría.</Text>
        ) : (
          issues.map((f) => <FindingBlock key={f.id + f.title} f={f} />)
        )}

        <View style={styles.footer} fixed>
          <Text>VibeAuditt — {hostname(report.url)}</Text>
          <Text render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} />
        </View>
      </Page>
    </Document>
  );
}

/** Genera el PDF y abre el diálogo de guardado. Devuelve la ruta o null. */
export async function exportReportPdf(report: AuditReport): Promise<string | null> {
  const blob = await pdf(<ReportDoc report={report} />).toBlob();
  const buf = new Uint8Array(await blob.arrayBuffer());
  const safeHost = hostname(report.url).replace(/[^a-z0-9.-]/gi, "_");
  return saveReportPdf(buf, `vibeauditt-${safeHost}.pdf`);
}
