import React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const ACLAIS_APPROVAL = "http://127.0.0.1:8765/approve";

type ToolKey = "report_formatter" | "invoice_analyzer";
type ToolAvailability = {
  status: "ready" | "protection_unavailable";
  tools: Record<ToolKey, boolean>;
};
type AvailabilityState =
  | { kind: "checking" }
  | { kind: "unavailable" }
  | ({ kind: "connected" } & ToolAvailability);

function parseAvailability(value: unknown): ToolAvailability | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !== "schema_version,status,tools" ||
    record.schema_version !== 1 ||
    (record.status !== "ready" && record.status !== "protection_unavailable") ||
    typeof record.tools !== "object" ||
    record.tools === null
  ) {
    return null;
  }
  const tools = record.tools as Record<string, unknown>;
  if (
    record.status === "protection_unavailable" &&
    (tools.report_formatter !== false || tools.invoice_analyzer !== false)
  ) {
    return null;
  }
  if (
    Object.keys(tools).sort().join(",") !== "invoice_analyzer,report_formatter" ||
    typeof tools.report_formatter !== "boolean" ||
    typeof tools.invoice_analyzer !== "boolean"
  ) {
    return null;
  }
  return {
    status: record.status,
    tools: {
      report_formatter: tools.report_formatter,
      invoice_analyzer: tools.invoice_analyzer,
    },
  };
}

function availabilityLabel(state: AvailabilityState, tool: ToolKey): string {
  if (state.kind === "checking") return "CHECKING";
  if (state.kind === "unavailable") return "ACLAIS UNAVAILABLE";
  if (state.status !== "ready") return "PROTECTION UNAVAILABLE";
  return state.tools[tool] ? "AVAILABLE" : "NOT INSTALLED";
}

function actionLabel(state: AvailabilityState, tool: ToolKey): string {
  const label = availabilityLabel(state, tool);
  if (label === "AVAILABLE") return "Continue to review";
  if (label === "CHECKING") return "Checking availability...";
  return label === "NOT INSTALLED" ? "Not installed" : "Unavailable";
}

function approvalUrl(toolId: string): string {
  const url = new URL(ACLAIS_APPROVAL);
  url.searchParams.set("tool_id", toolId);
  url.searchParams.set("launch_source_claim", "document_tools");
  return url.toString();
}

function DocumentMark({ type }: { type: "format" | "invoice" }) {
  return (
    <span className={`tool-mark tool-mark-${type}`} aria-hidden="true">
      {type === "format" ? (
        <svg viewBox="0 0 32 32" fill="none">
          <path d="M9 5.5h9.5L24 11v15.5H9z" />
          <path d="M18 5.5V11h6M13 16h7M13 20h7M13 24h4" />
          <path d="m7 13-2 3 2 3" />
        </svg>
      ) : (
        <svg viewBox="0 0 32 32" fill="none">
          <path d="M7 6.5h18v19H7z" />
          <path d="M11 11.5h10M11 16h3m4 0h3M11 20.5h3m4 0h3" />
        </svg>
      )}
    </span>
  );
}

function Arrow() {
  return (
    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <path d="M4 10h11M10 5l5 5-5 5" />
    </svg>
  );
}

function ShieldMark() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 3.5 19 6v5.2c0 4.4-2.7 7.4-7 9.3-4.3-1.9-7-4.9-7-9.3V6z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function App() {
  const [availability, setAvailability] = React.useState<AvailabilityState>({ kind: "checking" });

  React.useEffect(() => {
    let active = true;
    void fetch("/availability.json", { credentials: "omit", cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("availability unavailable");
        return response.json() as Promise<unknown>;
      })
      .then((value) => {
        if (!active) return;
        const parsed = parseAvailability(value);
        setAvailability(parsed ? { kind: "connected", ...parsed } : { kind: "unavailable" });
      })
      .catch(() => {
        if (active) setAvailability({ kind: "unavailable" });
      });
    return () => { active = false; };
  }, []);

  const reportAvailable = availability.kind === "connected" && availability.status === "ready" && availability.tools.report_formatter;
  const invoiceAvailable = availability.kind === "connected" && availability.status === "ready" && availability.tools.invoice_analyzer;

  return (
    <div className="page-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="topbar">
        <a className="brand" href="/" aria-label="Document Tools home">
          <span className="brand-symbol" aria-hidden="true">
            <svg viewBox="0 0 32 32" fill="none">
              <path d="M7.5 5.5h12l6 6v15h-18z" />
              <path d="M19.5 5.5v6h6M11.5 17h10M11.5 21h7" />
            </svg>
          </span>
          <span>Document Tools</span>
        </a>
        <div className="topbar-note"><span className="local-dot" />Local workspace</div>
      </header>

      <main className="main-content">
        <section className="intro" aria-labelledby="page-title">
          <div className="eyebrow"><span className="eyebrow-line" />A CLEARER WAY TO WORK WITH DOCUMENTS</div>
          <h1 id="page-title">Everyday documents,<br /><span>thoughtfully handled.</span></h1>
          <p className="intro-copy">
            A small set of focused tools for polishing reports and preparing the details you need.
          </p>
        </section>

        <section className="tools-grid" aria-label="Available document tools">
          <article className={`tool-card ${reportAvailable ? "tool-card-ready" : "tool-card-pending"}`}>
            <div className="card-topline">
              <DocumentMark type="format" />
              <span className={`availability ${reportAvailable ? "" : "availability-pending"}`} role="status"><span className="availability-dot" />{availabilityLabel(availability, "report_formatter")}</span>
            </div>
            <div className="tool-copy">
              <span className="tool-index">01 / REPORTS</span>
              <h2>Format a report</h2>
              <p>Bring structure to a Markdown report with consistent headings, clean spacing, and a table of contents.</p>
            </div>
            {reportAvailable ? <a className="primary-action" href={approvalUrl("report_formatter")}><span>Continue to review</span><Arrow /></a> : <button className="primary-action action-disabled" type="button" disabled><span>{actionLabel(availability, "report_formatter")}</span></button>}
            <p className="card-footnote"><span className="shield-icon"><ShieldMark /></span>Review and approve in ACLAIS before work begins.</p>
          </article>

          <article className={`tool-card ${invoiceAvailable ? "tool-card-ready" : "tool-card-pending"}`} aria-labelledby="invoice-title">
            <div className="card-topline">
              <DocumentMark type="invoice" />
              <span className={`availability ${invoiceAvailable ? "" : "availability-pending"}`} role="status"><span className="availability-dot" />{availabilityLabel(availability, "invoice_analyzer")}</span>
            </div>
            <div className="tool-copy">
              <span className="tool-index">02 / INVOICES</span>
              <h2 id="invoice-title">Extract invoice details</h2>
              <p>Organize invoice fields and totals into a clear, reviewable summary.</p>
            </div>
            {invoiceAvailable ? <a className="primary-action" href={approvalUrl("invoice_analyzer")}><span>Continue to review</span><Arrow /></a> : <button className="primary-action action-disabled" type="button" disabled><span>{actionLabel(availability, "invoice_analyzer")}</span></button>}
            <p className="card-footnote"><span className="shield-icon"><ShieldMark /></span>Review and approve in ACLAIS before work begins.</p>
          </article>
        </section>

        <section className="privacy-note" aria-label="How the workspace works">
          <span className="privacy-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none"><path d="M12 3.5 19 6v5.2c0 4.4-2.7 7.4-7 9.3-4.3-1.9-7-4.9-7-9.3V6z"/><path d="m9 12 2 2 4-4"/></svg>
          </span>
          <div><strong>Your documents stay in your workspace.</strong><span>Choose a trusted document and review the action on ACLAIS before anything starts.</span></div>
        </section>
      </main>

      <footer className="page-footer"><span>ACLAIS · DOCUMENT TOOLS</span><span>Local by design</span></footer>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode><App /></React.StrictMode>,
);
