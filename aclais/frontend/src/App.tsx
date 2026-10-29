import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { components } from "./generated/api";

type HealthResponse = components["schemas"]["HealthResponse"];
type DocumentSummary = components["schemas"]["DocumentSummary"];
type TaskSummary = components["schemas"]["TaskSummary"];
type TaskDetail = components["schemas"]["TaskDetailResponse"];
type EventRecord = components["schemas"]["EventRecord"];
type EvidenceResponse = components["schemas"]["EvidenceResponse"];
type EvidenceCheck = components["schemas"]["EvidenceCheck"];
type OutputMetadata = components["schemas"]["OutputMetadata"];
type TaskStatus = components["schemas"]["TaskStatus"];

type ApprovalConfig = {
  tool_id: "report_formatter" | "invoice_analyzer";
  launch_source_claim: "document_tools";
  approval_context: string;
  observed_origin: string | null;
  observed_referer: string | null;
};

type ApiFailure = Error & { status: number; code?: string };
type View = "workspace" | "activity";
type Incident = components["schemas"]["Incident"];

const TERMINAL: TaskStatus[] = ["COMPLETED", "BLOCKED", "FAILED", "CANCELLED"];

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { credentials: "same-origin", ...init });
  } catch {
    throw Object.assign(new Error("The local ACLAIS service could not be reached."), {
      status: 0,
      code: "DISCONNECTED",
    }) satisfies ApiFailure;
  }

  if (!response.ok) {
    let message = response.status === 401 ? "Your owner session has expired." : "The request could not be completed.";
    let code: string | undefined;
    try {
      const body = (await response.json()) as components["schemas"]["ErrorResponse"];
      message = body.error.message;
      code = body.error.code;
    } catch {
      // Keep the status-based message when a service returns a non-contract body.
    }
    throw Object.assign(new Error(message), { status: response.status, code }) satisfies ApiFailure;
  }
  return (await response.json()) as T;
}

function readApprovalConfig(): ApprovalConfig | null {
  const value = document.getElementById("root")?.getAttribute("data-approval");
  if (!value) return null;
  try {
    const candidate = JSON.parse(value) as Partial<ApprovalConfig>;
    if (
      (candidate.tool_id === "report_formatter" || candidate.tool_id === "invoice_analyzer") &&
      candidate.launch_source_claim === "document_tools" &&
      typeof candidate.approval_context === "string"
    ) {
      return {
        tool_id: candidate.tool_id,
        launch_source_claim: candidate.launch_source_claim,
        approval_context: candidate.approval_context,
        observed_origin: typeof candidate.observed_origin === "string" ? candidate.observed_origin : null,
        observed_referer: typeof candidate.observed_referer === "string" ? candidate.observed_referer : null,
      };
    }
  } catch {
    return null;
  }
  return null;
}

function csrfToken(): string | null {
  const prefix = "aclais_owner_csrf=";
  const value = document.cookie.split(";").map((item) => item.trim()).find((item) => item.startsWith(prefix));
  return value ? decodeURIComponent(value.slice(prefix.length)) : null;
}

function isActive(status: TaskStatus | undefined): boolean {
  return status !== undefined && !TERMINAL.includes(status);
}

function taskLabel(status: TaskStatus): string {
  const labels: Record<TaskStatus, string> = {
    CREATED: "Queued",
    PREPARING: "Preparing",
    RUNNING: "Running",
    REVOKING: "Stopping",
    VERIFYING: "Verifying",
    COMPLETED: "Completed",
    BLOCKED: "Blocked",
    FAILED: "Failed",
    CANCELLED: "Cancelled",
  };
  return labels[status];
}

function taskName(toolId: string): string {
  return toolId === "invoice_analyzer" ? "Invoice Analyzer" : "Report Formatter";
}

function localDate(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Not recorded";
  return new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Kolkata",
  }).format(date) + " IST";
}

function bytes(value: number | null): string {
  if (value === null) return "Size not recorded";
  if (value < 1024) return `${value} bytes`;
  return `${(value / 1024).toFixed(value < 10_240 ? 1 : 0)} KB`;
}

function statusTone(value: string): "good" | "warn" | "bad" | "quiet" {
  if (["pass", "ready", "terminated", "COMPLETED"].includes(value)) return "good";
  if (["fail", "failed", "unavailable", "BLOCKED", "FAILED"].includes(value)) return "bad";
  if (["pending", "unknown", "unverified", "PREPARING", "RUNNING", "REVOKING", "VERIFYING"].includes(value)) return "warn";
  return "quiet";
}

function humanStatus(value: string): string {
  const words = value.replaceAll("_", " ").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function incidentHeadline(incident: Incident, evidenceStatus?: EvidenceResponse["status"]): string {
  if (incident.containment_status === "failed") return "Containment failed";
  if (incident.integrity_status === "fail" || incident.confidentiality_status === "fail") return "Verification failed";
  if (evidenceStatus === "pending" || incident.integrity_status === "pending" || incident.confidentiality_status === "pending") return "Verification pending";
  if (incident.integrity_status === "unknown" || incident.confidentiality_status === "unknown") return "Verification incomplete";
  if (incident.containment_status === "terminated" && incident.integrity_status === "pass" && incident.confidentiality_status === "pass") return "Protected originals unchanged";
  return "Policy action recorded";
}

function incidentFailure(incident: Incident): boolean {
  return incident.containment_status === "failed" || incident.integrity_status === "fail" || incident.confidentiality_status === "fail";
}

function errorFor(error: unknown): ApiFailure {
  if (error instanceof Error && "status" in error) return error as ApiFailure;
  return Object.assign(new Error("The ACLAIS response could not be read."), { status: 0 }) as ApiFailure;
}

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 32 32" fill="none">
        <path d="M16 4.5 25 8v7.4c0 5.8-3.8 10.4-9 12.1-5.2-1.7-9-6.3-9-12.1V8l9-3.5Z" stroke="currentColor" strokeWidth="1.7" />
        <path d="m11.6 15.9 2.9 2.8 5.9-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

function Icon({ name }: { name: "grid" | "activity" | "file" | "arrow" | "close" | "shield" | "clock" | "chevron" | "spark" | "alert" | "refresh" | "external" }) {
  const paths: Record<typeof name, ReactNode> = {
    grid: <><rect x="3.5" y="3.5" width="7" height="7" rx="1.6" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.6" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.6" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.6" /></>,
    activity: <><path d="M3 12h4l2.2-6 4.1 12 2.4-6H21" /></>,
    file: <><path d="M7 3.5h7l4.5 4.6v12.4H7z" /><path d="M14 3.8v4.5h4.3M9.5 12h6M9.5 15.5h6" /></>,
    arrow: <><path d="M4 12h15M13 6l6 6-6 6" /></>,
    close: <><path d="m6 6 12 12M18 6 6 18" /></>,
    shield: <><path d="M12 3.2 19 6v5.8c0 4.6-2.9 8.1-7 9.7-4.1-1.6-7-5.1-7-9.7V6l7-2.8Z" /><path d="m9 11.8 2 2 4-4" /></>,
    clock: <><circle cx="12" cy="12" r="8.5" /><path d="M12 7v5l3.2 2" /></>,
    chevron: <><path d="m8 10 4 4 4-4" /></>,
    spark: <><path d="m12 3 1.6 5.4L19 10l-5.4 1.6L12 17l-1.6-5.4L5 10l5.4-1.6L12 3Z" /><path d="m19 15 .8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8L19 15Z" /></>,
    alert: <><path d="M12 3.5 21 19H3l9-15.5Z" /><path d="M12 9v4.5M12 16.5v.1" /></>,
    refresh: <><path d="M19 8.5A7.5 7.5 0 0 0 6.2 6L4 8.2M5 4v4.5h4.5M5 15.5A7.5 7.5 0 0 0 17.8 18L20 15.8M19 20v-4.5h-4.5" /></>,
    external: <><path d="M13 5h6v6M19 5l-8 8" /><path d="M17 13v5a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1h5" /></>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

export default function App() {
  const approval = useMemo(readApprovalConfig, []);
  return approval || window.location.pathname === "/approve" ? <ApprovalPage config={approval} /> : <Dashboard />;
}

function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [documents, setDocuments] = useState<DocumentSummary[]>([]);
  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [detail, setDetail] = useState<TaskDetail | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [output, setOutput] = useState<{ metadata: OutputMetadata; content: string } | null>(null);
  const [evidence, setEvidence] = useState<EvidenceResponse | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [view, setView] = useState<View>("workspace");
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(() => sessionStorage.getItem("aclais:selectedTaskId"));
  const [connected, setConnected] = useState(true);
  const connectedRef = useRef(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [cancelMessage, setCancelMessage] = useState<string | null>(null);
  const [incidentOpen, setIncidentOpen] = useState(false);
  const [advancedEvidence, setAdvancedEvidence] = useState(false);
  const refreshRef = useRef<() => Promise<void>>(async () => undefined);
  const refreshSequenceRef = useRef(0);
  const tasksRef = useRef<TaskSummary[]>([]);
  const cursorRef = useRef<{ taskId: string | null; seq: number }>({ taskId: null, seq: 0 });
  const outputIdRef = useRef<string | null>(null);
  const viewRef = useRef(view);
  const selectedTaskRef = useRef(selectedTaskId);
  const drawerTriggerRef = useRef<HTMLButtonElement | null>(null);
  const drawerRef = useRef<HTMLElement | null>(null);

  const refresh = useCallback(async () => {
    const refreshSequence = ++refreshSequenceRef.current;
    let nextTasks: TaskSummary[];
    let nextId: string | null = null;
    try {
      const [healthResult, documentsResult, tasksResult] = await Promise.all([
        requestJson<HealthResponse>("/api/health"),
        requestJson<components["schemas"]["DocumentListResponse"]>("/api/documents"),
        requestJson<components["schemas"]["TaskListResponse"]>(`/api/tasks?limit=${view === "activity" ? 50 : 20}`),
      ]);
      if (refreshSequence !== refreshSequenceRef.current) return;
      setHealth(healthResult);
      setDocuments(documentsResult.documents);
      nextTasks = tasksResult.tasks;
      tasksRef.current = nextTasks;
      setTasks(nextTasks);
      connectedRef.current = true;
      setConnected(true);
      setLoadError(null);
      setLoading(false);

      const saved = selectedTaskId && nextTasks.some((item) => item.task_id === selectedTaskId) ? selectedTaskId : null;
      const active = nextTasks.find((item) => isActive(item.status));
      nextId = saved ?? active?.task_id ?? nextTasks[0]?.task_id ?? null;
      if (nextId !== selectedTaskId) {
        setSelectedTaskId(nextId);
        if (nextId) sessionStorage.setItem("aclais:selectedTaskId", nextId);
        else sessionStorage.removeItem("aclais:selectedTaskId");
      }
    } catch (error) {
      if (refreshSequence !== refreshSequenceRef.current) return;
      const failure = errorFor(error);
      connectedRef.current = false;
      setConnected(false);
      setHealth(null);
      setLoadError(failure.message);
      setLoading(false);
      return;
    }

    if (!nextId) {
      setDetail(null);
      setEvents([]);
      setOutput(null);
      return;
    }

    try {
      const selected = nextTasks.find((item) => item.task_id === nextId);
      const fastPoll = selected ? isActive(selected.status) : false;
      const currentCursor = cursorRef.current.taskId === nextId ? cursorRef.current.seq : 0;
      if (cursorRef.current.taskId !== nextId) {
        cursorRef.current = { taskId: nextId, seq: 0 };
        outputIdRef.current = null;
        setEvents([]);
        setOutput(null);
      }
      const [nextDetail, eventResult] = await Promise.all([
        requestJson<TaskDetail>(`/api/tasks/${nextId}`),
        requestJson<components["schemas"]["EventsResponse"]>(`/api/tasks/${nextId}/events?after_seq=${currentCursor}`),
      ]);
      if (refreshSequence !== refreshSequenceRef.current) return;
      setDetail(nextDetail);
      if (eventResult.events.length) {
        setEvents((current) => {
          const merged = new Map(current.map((event) => [event.seq, event]));
          for (const event of eventResult.events) merged.set(event.seq, event);
          return [...merged.values()].sort((left, right) => left.seq - right.seq);
        });
      }
      cursorRef.current = { taskId: nextId, seq: Math.max(currentCursor, eventResult.last_seq) };
      const outputMetadata = nextDetail.output_metadata;
      if (outputMetadata && outputIdRef.current !== outputMetadata.output_id) {
        try {
          const response = await fetch(`/api/outputs/${outputMetadata.output_id}`, { credentials: "same-origin" });
          if (!response.ok) throw new Error("The verified output is temporarily unavailable.");
          const content = await response.text();
          if (refreshSequence !== refreshSequenceRef.current) return;
          setOutput({ metadata: outputMetadata, content });
          outputIdRef.current = outputMetadata.output_id;
        } catch {
          if (refreshSequence !== refreshSequenceRef.current) return;
          setOutput(null);
        }
      } else if (!outputMetadata) {
        outputIdRef.current = null;
        setOutput(null);
      }
      if (incidentOpen && nextDetail.incident_summary) {
        setEvidenceLoading(true);
        try {
          setEvidence(await requestJson<EvidenceResponse>(`/api/tasks/${nextId}/evidence`));
          setEvidenceError(null);
        } catch {
          setEvidence(null);
          setEvidenceError("The evidence endpoint did not return a current report.");
        } finally {
          setEvidenceLoading(false);
        }
      }
      if (!fastPoll && selected && !isActive(nextDetail.task.status)) {
        setCancelMessage(null);
      }
    } catch (error) {
      if (refreshSequence !== refreshSequenceRef.current) return;
      const failure = errorFor(error);
      setDetail(null);
      setEvents([]);
      setOutput(null);
      if (failure.status === 401) {
        connectedRef.current = false;
        setConnected(false);
        setHealth(null);
      }
      setLoadError(failure.message);
    }
  }, [incidentOpen, selectedTaskId, view]);

  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  useEffect(() => {
    const changed = viewRef.current !== view || selectedTaskRef.current !== selectedTaskId;
    viewRef.current = view;
    selectedTaskRef.current = selectedTaskId;
    if (changed) refreshRef.current();
  }, [selectedTaskId, view]);

  useEffect(() => {
    let stopped = false;
    let timer = 0;
    const poll = async () => {
      if (stopped) return;
      await refreshRef.current();
      if (stopped) return;
      const active = connectedRef.current && tasksRef.current.some((task) => isActive(task.status));
      timer = window.setTimeout(poll, active ? 500 : 2000);
    };
    void poll();
    const onFocus = () => refreshRef.current();
    window.addEventListener("focus", onFocus);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      window.removeEventListener("focus", onFocus);
    };
    // The effect is deliberately started once; the timer reads current state via refresh's latest callback.
  }, []);

  useEffect(() => {
    if (!incidentOpen || !detail?.incident_summary) return;
    let cancelled = false;
    setEvidenceLoading(true);
    void requestJson<EvidenceResponse>(`/api/tasks/${detail.task.task_id}/evidence`)
      .then((response) => { if (!cancelled) { setEvidence(response); setEvidenceError(null); } })
      .catch(() => { if (!cancelled) { setEvidence(null); setEvidenceError("The evidence endpoint did not return a current report."); } })
      .finally(() => { if (!cancelled) setEvidenceLoading(false); });
    return () => { cancelled = true; };
  }, [incidentOpen, detail?.task.task_id, detail?.incident_summary]);

  useEffect(() => {
    if (!incidentOpen) {
      drawerTriggerRef.current?.focus();
      return;
    }
    const drawer = drawerRef.current;
    const focusables = () => drawer?.querySelectorAll<HTMLElement>("button:not([disabled]), a[href], summary, [tabindex='0']") ?? [];
    focusables()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIncidentOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const items = [...focusables()];
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [incidentOpen]);

  const g1 = health?.checks.find((check) => check.id === "g1_protection");
  const healthState = !connected ? "disconnected" : health?.protection_ready && health.status === "ready" && g1?.status === "pass" ? "ready" : g1?.status === "fail" ? "unavailable" : "pending";
  const activeTask = detail ? isActive(detail.task.status) : false;

  const startApproval = (toolId: "report_formatter" | "invoice_analyzer") => {
    const query = new URLSearchParams({ tool_id: toolId, launch_source_claim: "document_tools" });
    window.location.assign(`/approve?${query.toString()}`);
  };

  const cancelSelected = async () => {
    if (!detail || !activeTask || busy) return;
    const csrf = csrfToken();
    if (!csrf) {
      setCancelMessage("Your owner session has expired. Reopen ACLAIS to sign in.");
      return;
    }
    setBusy(true);
    setCancelMessage(null);
    try {
      const result = await requestJson<components["schemas"]["CancelResponse"]>(`/api/tasks/${detail.task.task_id}/cancel`, {
        method: "POST",
        headers: { "X-CSRF-Token": csrf },
      });
      setCancelMessage(`Task state: ${taskLabel(result.status)}.`);
      await refresh();
    } catch (error) {
      setCancelMessage(errorFor(error).message);
    } finally {
      setBusy(false);
    }
  };

  const title = view === "activity" ? "Activity" : "Workspace";
  const incident = detail?.incident_summary ?? null;

  return (
    <div className="app-frame">
      <aside className="rail" aria-label="Primary navigation">
        <a className="brand" href="/owner" aria-label="ACLAIS Workspace">
          <BrandMark />
          <span>ACLAIS</span>
        </a>
        <div className="rail-caption">OWNER CONSOLE</div>
        <nav className="rail-nav" aria-label="Workspace views">
          <button className={`nav-item ${view === "workspace" ? "active" : ""}`} onClick={() => setView("workspace")} aria-current={view === "workspace" ? "page" : undefined}>
            <Icon name="grid" /><span>Workspace</span>
          </button>
          <button className={`nav-item ${view === "activity" ? "active" : ""}`} onClick={() => setView("activity")} aria-current={view === "activity" ? "page" : undefined}>
            <Icon name="activity" /><span>Activity</span>
            {tasks.length > 0 && <span className="nav-count">{tasks.length}</span>}
          </button>
        </nav>
        <div className="rail-bottom">
          <div className="rail-health-label">PROTECTION</div>
          <HealthCard state={healthState} summary={g1?.summary ?? loadError} compact />
          <div className="rail-footnote">Local owner session</div>
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <div className="topbar-title">
            <span className="eyebrow">ACLAIS / OWNER</span>
            <span className="topbar-separator">/</span>
            <span>{title}</span>
          </div>
          <div className="topbar-actions">
            <span className={`connection-pill ${connected ? "online" : "offline"}`}>
              <span className="connection-dot" />{connected ? "Connected" : "Disconnected"}
            </span>
            <button className="icon-button refresh-button" onClick={() => refreshRef.current()} aria-label="Refresh workspace" title="Refresh workspace">
              <Icon name="refresh" />
            </button>
            <span className="owner-avatar" aria-label="Owner session">O</span>
          </div>
        </header>

    <main className="content-scroll" id="main-content">
          <section className="page-heading">
            <div>
              <div className="page-kicker">PRIVATE WORKSPACE</div>
              <h1>{title}</h1>
              <p className="page-intro">Your documents and approved local actions, in one clear view.</p>
            </div>
            <div className="heading-health"><HealthCard state={healthState} summary={g1?.summary ?? loadError} /></div>
          </section>

          {!connected && <ConnectionNotice message={loadError ?? "The local service is not responding."} onRetry={() => refreshRef.current()} />}
          {connected && healthState === "unavailable" && <ProtectionNotice message={g1?.summary ?? "The protection preflight reported a failure."} />}
          {connected && healthState === "pending" && <PendingNotice message={g1?.summary ?? "Protection verification has not completed."} />}
          {loadError && connected && <div className="inline-error" role="status">{loadError}</div>}

          {view === "workspace" ? (
            <div className="workspace-layout">
              <div className="workspace-main">
                <section className="section-block" aria-labelledby="documents-heading">
                  <div className="section-heading">
                    <div><div className="section-kicker">YOUR FILES</div><h2 id="documents-heading">Documents</h2></div>
                    <span className="section-meta">{documents.length} registered</span>
                  </div>
                  {loading ? <LoadingPanel label="Loading registered documents" /> : documents.length === 0 ? <EmptyPanel title="No documents registered" detail="The trusted document registry returned no entries." /> : (
                    <div className="document-list">
                      {documents.map((item) => <DocumentCard key={item.id} item={item} />)}
                    </div>
                  )}
                </section>

                <section className="section-block tools-section" aria-labelledby="tools-heading">
                  <div className="section-heading">
                    <div><div className="section-kicker">FIXED TOOL REGISTRY</div><h2 id="tools-heading">Choose an action</h2></div>
                    <span className="section-meta">Owner approval required</span>
                  </div>
                  <div className="tool-grid">
                    <ToolCard title="Report Formatter" detail="Create a clean, structured version of a selected report." documentLabel={documents.find((item) => item.id === "doc-report")?.display_name ?? "Registered input unavailable"} tone="blue" registrationLabel="FIXED TOOL" buttonLabel="Review and approve" onClick={() => startApproval("report_formatter")} disabled={!connected || !documents.some((item) => item.id === "doc-report")} />
                    <ToolCard title="Invoice Analyzer" detail="This utility will be available after the Report Formatter checkpoint is verified." documentLabel={documents.find((item) => item.id === "doc-invoice")?.display_name ?? "Registered input unavailable"} tone="violet" registrationLabel="NOT INSTALLED" buttonLabel="Unavailable" onClick={() => undefined} disabled />
                  </div>
                </section>

                <section className="section-block recent-section" aria-labelledby="recent-heading">
                  <div className="section-heading">
                    <div><div className="section-kicker">PERSISTED TASK STATE</div><h2 id="recent-heading">Recent activity</h2></div>
                    <button className="text-button" onClick={() => setView("activity")}>View all <Icon name="arrow" /></button>
                  </div>
                  {loading ? <LoadingPanel label="Loading task history" /> : tasks.length === 0 ? <EmptyPanel title="No tasks yet" detail="Approved tasks will appear here after an owner action." /> : (
                    <div className="recent-list">
                      {tasks.slice(0, 4).map((task) => <TaskRow key={task.task_id} task={task} selected={task.task_id === selectedTaskId} onClick={() => { setSelectedTaskId(task.task_id); sessionStorage.setItem("aclais:selectedTaskId", task.task_id); setView("activity"); }} documents={documents} />)}
                    </div>
                  )}
                </section>
              </div>

              <aside className="workspace-side" aria-label="Selected task details">
                <SelectedTaskCard detail={detail} events={events} output={output} documents={documents} connected={connected} onIncident={(button) => { drawerTriggerRef.current = button; setIncidentOpen(true); }} onCancel={cancelSelected} busy={busy} cancelMessage={cancelMessage} />
              </aside>
            </div>
          ) : (
            <div className="activity-layout">
              <section className="activity-panel" aria-labelledby="activity-heading">
                <div className="section-heading activity-title-row">
                  <div><div className="section-kicker">OWNER AUDIT VIEW</div><h2 id="activity-heading">Task history</h2></div>
                  <span className="section-meta">Ordered by the controller</span>
                </div>
                {loading ? <LoadingPanel label="Loading task history" /> : tasks.length === 0 ? <EmptyPanel title="No activity recorded" detail="Task events will appear here after an approved action." /> : (
                  <div className="activity-columns">
                    <div className="task-list" aria-label="Tasks">
                      {tasks.map((task) => <TaskRow key={task.task_id} task={task} selected={task.task_id === selectedTaskId} onClick={() => { setSelectedTaskId(task.task_id); sessionStorage.setItem("aclais:selectedTaskId", task.task_id); }} documents={documents} />)}
                    </div>
                    <div className="activity-detail">
                      {detail ? <TaskDetailView detail={detail} events={events} output={output} documents={documents} connected={connected} onIncident={(button) => { drawerTriggerRef.current = button; setIncidentOpen(true); }} onCancel={cancelSelected} busy={busy} cancelMessage={cancelMessage} /> : <EmptyPanel title="Select a task" detail="Choose a persisted task to inspect its status and ordered events." />}
                    </div>
                  </div>
                )}
              </section>
            </div>
          )}
        </main>
      </div>

      {incidentOpen && incident && detail && (
        <div className="drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setIncidentOpen(false); }}>
          <aside className="incident-drawer" ref={drawerRef} role="dialog" aria-modal="true" aria-labelledby="incident-title" tabIndex={-1}>
            <div className="drawer-header">
              <div><div className="section-kicker">INCIDENT RECORD</div><h2 id="incident-title">Protection event</h2></div>
              <button className="icon-button" onClick={() => setIncidentOpen(false)} aria-label="Close incident details"><Icon name="close" /></button>
            </div>
            <div className={`incident-banner ${incidentFailure(incident) ? "danger" : "calm"}`}>
              <span className="incident-icon"><Icon name={incidentFailure(incident) ? "alert" : "shield"} /></span>
              <div><strong>{incidentHeadline(incident, evidence?.status)}</strong><p>{incident.policy_reason === "DOCUMENT_OUT_OF_SCOPE" ? "The worker requested a document outside its approved selection." : "The worker attempted a change to a protected original."}</p></div>
            </div>
            <div className="drawer-section">
              <div className="drawer-section-title">Observed response</div>
              <StatusLine label="Containment" value={incident.containment_status} />
              <StatusLine label="File integrity" value={incident.integrity_status} />
              <StatusLine label="Confidentiality" value={incident.confidentiality_status} />
              <StatusLine label="Independent evidence" value={evidence?.status ?? "pending"} />
              {evidence?.status === "complete" && evidence.report && <StatusLine label="Worker termination" value={evidence.report.worker_termination_confirmed ? "pass" : "unknown"} />}
            </div>
            <div className="drawer-section">
              <div className="drawer-section-title">Evidence sources</div>
              <div className="source-chips">
                {(["controller", "broker", "worker_reported", "verifier", "receiver"] as const).map((source) => {
                  const count = evidence?.report?.checks.filter((check) => check.source === source).length ?? events.filter((event) => event.source === source).length;
                  return count > 0 ? <span className={`source-chip source-${source}`} key={source}>{humanStatus(source)} <b>{count}</b></span> : null;
                })}
                {evidence?.report?.checks.length === 0 && <span className="muted-copy">No completed evidence checks are available yet.</span>}
              </div>
            </div>
            <div className="drawer-section evidence-summary">
              <div className="drawer-section-title">Independent verification</div>
            {evidenceError ? <div className="verification-unavailable"><Icon name="alert" />{evidenceError} Verification remains unknown.</div> : evidenceLoading ? <div className="verification-pending"><span className="status-dot warn" />Loading the current evidence report.</div> : evidence?.status === "pending" ? <div className="verification-pending"><span className="status-dot warn" />The controller has not reported a completed verifier result.</div> : evidence?.status === "complete" && evidence.report ? <div className="check-list">{evidence.report.checks.map((check) => <EvidenceCheckRow key={`${check.source}-${check.id}`} check={check} />)}</div> : <div className="verification-unavailable"><Icon name="alert" />No current verification report is available. Verification remains unknown.</div>}
            </div>
            <button className="disclosure-button" onClick={() => setAdvancedEvidence((value) => !value)} aria-expanded={advancedEvidence}>
              <span>Advanced evidence</span><Icon name="chevron" />
            </button>
            {advancedEvidence && <AdvancedEvidence evidence={evidence} events={events} detail={detail} />}
            <div className="drawer-footer"><span>Evidence remains separated by source.</span><span>Owner view · local only</span></div>
          </aside>
        </div>
      )}
      <div className="sr-only" aria-live="polite" aria-atomic="true">{incident && incidentOpen ? "Incident evidence opened." : ""}</div>
    </div>
  );
}

function HealthCard({ state, summary, compact = false }: { state: string; summary?: string | null; compact?: boolean }) {
  const details: Record<string, { title: string; tag: string }> = {
    ready: { title: "Workspace protection ready", tag: "READY" },
    pending: { title: "Verification pending", tag: "PENDING" },
    unavailable: { title: "Protection unavailable", tag: "UNAVAILABLE" },
    disconnected: { title: "ACLAIS disconnected", tag: "OFFLINE" },
  };
  const value = details[state] ?? details.pending;
  return <div className={`health-card health-${state} ${compact ? "compact" : ""}`}>
    <span className="health-symbol"><Icon name={state === "ready" ? "shield" : state === "unavailable" ? "alert" : "clock"} /></span>
    <div className="health-copy"><strong>{value.title}</strong>{!compact && <span>{summary ?? "Waiting for a current protection check."}</span>}</div>
    <span className="health-tag">{value.tag}</span>
  </div>;
}

function ConnectionNotice({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="state-notice disconnected-notice" role="status"><span className="notice-mark"><Icon name="alert" /></span><div><strong>ACLAIS is disconnected</strong><p>{message} No current protection state is available.</p></div><button className="secondary-button" onClick={onRetry}>Retry</button></div>;
}

function ProtectionNotice({ message }: { message: string }) {
  return <div className="state-notice unavailable-notice" role="status"><span className="notice-mark"><Icon name="alert" /></span><div><strong>Protection unavailable</strong><p>{message}</p></div></div>;
}

function PendingNotice({ message }: { message: string }) {
  return <div className="state-notice pending-notice" role="status"><span className="notice-mark"><Icon name="clock" /></span><div><strong>Verification pending</strong><p>{message}</p></div></div>;
}

function DocumentCard({ item }: { item: DocumentSummary }) {
  return <article className="document-card">
    <span className="document-icon"><Icon name="file" /></span>
    <div className="document-name"><strong>{item.display_name}</strong><span>{item.media_type} <i /> {bytes(item.size_bytes)}</span></div>
    <StatusBadge value={item.protection_status} />
    <div className="document-verified"><span>Last verified</span><strong>{localDate(item.last_verified_at)}</strong></div>
  </article>;
}

function ToolCard({ title, detail, documentLabel, tone, registrationLabel, buttonLabel, onClick, disabled }: { title: string; detail: string; documentLabel: string; tone: "blue" | "violet"; registrationLabel: string; buttonLabel: string; onClick: () => void; disabled: boolean }) {
  return <article className={`tool-card tool-${tone}`}>
    <div className="tool-card-top"><span className="tool-icon"><Icon name="spark" /></span><span className="tool-registration">{registrationLabel}</span></div>
    <h3>{title}</h3><p>{detail}</p>
    <div className="tool-input"><Icon name="file" /><span>Registered input</span><strong>{documentLabel}</strong></div>
    <button className="primary-button" onClick={onClick} disabled={disabled} aria-label={disabled ? `${title} unavailable` : `Review ${title} approval`}><span>{buttonLabel}</span>{!disabled && <Icon name="arrow" />}</button>
  </article>;
}

function TaskRow({ task, selected, onClick, documents }: { task: TaskSummary; selected: boolean; onClick: () => void; documents: DocumentSummary[] }) {
  const doc = documents.find((item) => item.id === task.selected_document_id);
  return <button className={`task-row ${selected ? "selected" : ""}`} onClick={onClick} aria-current={selected ? "true" : undefined}>
    <span className={`task-state-dot tone-${statusTone(task.status)}`} />
    <span className="task-row-copy"><strong>{taskName(task.tool_id)}</strong><span>{doc?.display_name ?? "Registered document"}</span></span>
    <span className="task-row-end"><StatusBadge value={task.status} /><span>{localDate(task.finished_at ?? task.created_at)}</span></span>
    <Icon name="chevron" />
  </button>;
}

function SelectedTaskCard({ detail, events, output, documents, connected, onIncident, onCancel, busy, cancelMessage }: { detail: TaskDetail | null; events: EventRecord[]; output: { metadata: OutputMetadata; content: string } | null; documents: DocumentSummary[]; connected: boolean; onIncident: (button: HTMLButtonElement) => void; onCancel: () => void; busy: boolean; cancelMessage: string | null }) {
  if (!detail) return <section className="side-card selected-task-card"><div className="side-card-heading"><span className="section-kicker">CURRENT TASK</span><span className="side-empty-icon"><Icon name="clock" /></span></div><h2>No selected task</h2><p>After an approved action, its recorded status and useful output will appear here.</p><div className="empty-line" /></section>;
  return <TaskDetailView detail={detail} events={events} output={output} documents={documents} connected={connected} compact onIncident={onIncident} onCancel={onCancel} busy={busy} cancelMessage={cancelMessage} />;
}

function TaskDetailView({ detail, events, output, documents, connected, compact = false, onIncident, onCancel, busy, cancelMessage }: { detail: TaskDetail; events: EventRecord[]; output: { metadata: OutputMetadata; content: string } | null; documents: DocumentSummary[]; connected: boolean; compact?: boolean; onIncident: (button: HTMLButtonElement) => void; onCancel: () => void; busy: boolean; cancelMessage: string | null }) {
  const { task, output_metadata: metadata, incident_summary: incident } = detail;
  const docName = documents.find((item) => item.id === task.selected_document_id)?.display_name ?? "Registered document";
  const sortedEvents = [...events].sort((left, right) => left.seq - right.seq);
  const showOutput = Boolean(metadata && output);
  return <section className={`side-card task-detail-card ${compact ? "compact-detail" : ""}`} aria-label="Selected task">
    <div className="side-card-heading"><span className="section-kicker">{compact ? "CURRENT TASK" : "TASK DETAILS"}</span><StatusBadge value={task.status} /></div>
    <div className="task-detail-title"><div className="task-tool-glyph"><Icon name={task.tool_id === "invoice_analyzer" ? "file" : "spark"} /></div><div><h2>{taskName(task.tool_id)}</h2><span>{docName}</span></div></div>
    <div className="task-meta-grid"><div><span>Started</span><strong>{localDate(task.started_at ?? task.created_at)}</strong></div><div><span>Permission</span><strong>{detail.contract_summary ? "Selected document only" : "Not available"}</strong></div></div>
    {incident && <div className={`incident-callout ${incidentFailure(incident) ? "is-danger" : ""}`}><span className="incident-callout-icon"><Icon name="alert" /></span><div><strong>{incidentHeadline(incident, task.status === "VERIFYING" ? "pending" : undefined)}</strong><span>{incident.integrity_status === "pending" || incident.integrity_status === "unknown" || incident.confidentiality_status === "pending" || incident.confidentiality_status === "unknown" ? "The file verification result is not conclusive." : "Review the recorded evidence and source."}</span></div><button className="text-button" onClick={(event) => onIncident(event.currentTarget)}>View details</button></div>}
    {activeForCard(task.status) && <div className={`progress-block ${connected ? "" : "is-stale"}`}><div className="progress-heading"><span>{task.status === "PREPARING" ? "Preparing restricted workspace" : task.status === "VERIFYING" ? "Verifying protected files" : task.status === "REVOKING" ? "Stopping worker" : "Approved action in progress"}</span><span className={`live-tag ${connected ? "" : "is-stale"}`}><i /> {connected ? "Live" : "Connection lost"}</span></div><div className="progress-track"><span className="progress-fill" /></div></div>}
    <div className="result-heading"><div><span className="section-kicker">USEFUL OUTPUT</span><h3>{metadata ? metadata.output_kind === "invoice_json" ? "Extracted invoice fields" : "Formatted report" : "No verified output yet"}</h3></div>{metadata && <span className="output-size">{bytes(metadata.decoded_bytes)}</span>}</div>
    {showOutput && output ? <div className="output-preview" aria-label="Inert task output"><pre>{output.content.slice(0, 12_000)}{output.content.length > 12_000 ? "\n… Output preview clipped." : ""}</pre><div className="output-foot"><span>{incident ? "Generated by a tool that was stopped" : "Verified published output"}</span><span>SHA-256 · {output.metadata.sha256.slice(0, 12)}…</span></div></div> : <div className="output-empty"><span className="output-empty-icon"><Icon name="file" /></span><span>{task.status === "COMPLETED" ? "No output was published for this task." : "A result appears after ACLAIS verifies a published output."}</span></div>}
    <div className="timeline-heading"><span className="section-kicker">EVENT TIMELINE</span><span>{events.length} recorded</span></div>
    {sortedEvents.length ? <ol className="event-timeline">{sortedEvents.slice(-6).map((event) => <EventLine key={event.seq} event={event} />)}</ol> : <div className="timeline-empty">No task events have been returned yet.</div>}
    <div className="task-actions">{activeForCard(task.status) && <button className="secondary-button" onClick={onCancel} disabled={busy}>{busy ? "Stopping…" : "Stop task"}</button>}{incident && !compact && <button className="text-button" onClick={(event) => onIncident(event.currentTarget)}>Open incident evidence <Icon name="arrow" /></button>}</div>
    {cancelMessage && <div className="action-status" role="status">{cancelMessage}</div>}
  </section>;
}

function activeForCard(status: TaskStatus): boolean { return isActive(status); }

function EventLine({ event }: { event: EventRecord }) {
  return <li className={`event-line event-${event.source}`} data-event-seq={event.seq}>
    <span className="event-marker" />
    <div className="event-line-copy"><div className="event-line-top"><strong>{eventTitle(event)}</strong><time dateTime={event.timestamp}>{localDate(event.timestamp)}</time></div><p>{event.message.slice(0, 220)}</p><span className={`event-source source-${event.source}`}>{humanStatus(event.source)}</span></div>
  </li>;
}

function eventTitle(event: EventRecord): string {
  if (event.source === "worker_reported") return "Worker reported";
  if (event.decision === "deny") return "Broker denied operation";
  if (event.source === "verifier") return "Independent verifier";
  if (event.source === "broker" && event.decision === "allow") return "Broker allowed operation";
  return humanStatus(event.kind);
}

function StatusLine({ label, value }: { label: string; value: string }) {
  return <div className="status-line"><span>{label}</span><StatusBadge value={value} /></div>;
}

function StatusBadge({ value }: { value: string }) {
  const tone = statusTone(value);
  return <span className={`status-badge badge-${tone}`}><i />{humanStatus(value)}</span>;
}

function EvidenceCheckRow({ check }: { check: EvidenceCheck }) {
  return <div className="evidence-check"><span className={`evidence-check-dot tone-${statusTone(check.status)}`} /><div><strong>{check.id.replaceAll("_", " ")}</strong><span>{check.expected}</span></div><span className={`event-source source-${check.source}`}>{humanStatus(check.source)}</span><StatusBadge value={check.status} /></div>;
}

function AdvancedEvidence({ evidence, events, detail }: { evidence: EvidenceResponse | null; events: EventRecord[]; detail: TaskDetail }) {
  const report = evidence?.report;
  return <div className="advanced-evidence">
    <CopyValue label="Task ID" value={detail.task.task_id} />
    {report && <CopyValue label="Source digest" value={report.tested_source_sha256} />}
    {events.filter((event) => event.source === "broker").map((event) => <div className="advanced-row" key={event.seq}><span>Broker event {event.seq}</span><code>{event.operation} · {event.target_document_id ?? "Output slot"} · {event.decision} · {event.reason_code}</code></div>)}
    <div className="advanced-row"><span>Task / run</span><code>{detail.task.task_id} / {detail.task.run_id}</code></div>
    <div className="advanced-row"><span>Selected target</span><code>{detail.task.selected_document_id}</code></div>
    {report && <><div className="advanced-row"><span>Tested source</span><code>{report.tested_source_revision ?? `sha256:${report.tested_source_sha256}`}</code></div><div className="advanced-row"><span>Process identity</span><code>{report.controller_process_observation ? `PID ${report.controller_process_observation.pid} · ${report.controller_process_observation.worker_sid}` : "Not recorded"}</code></div><div className="advanced-row"><span>Worker termination</span><code>{report.worker_termination_confirmed ? "Confirmed" : "Unknown"}</code></div></>}
    <div className="advanced-row"><span>Event source order</span><code>{events.map((event) => `${event.seq}:${event.source}`).join(" · ") || "No events returned"}</code></div>
    {report?.checks.map((check) => <div className="advanced-row" key={check.id}><span>{check.id.replaceAll("_", " ")} · {check.source}</span><code>{check.status} · {check.observed}</code></div>)}
  </div>;
}

function CopyValue({ label, value }: { label: string; value: string }) {
  const [message, setMessage] = useState("");
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setMessage(`${label} copied.`); }
    catch { setMessage(`${label} could not be copied.`); }
  };
  return <div className="advanced-row"><button className="secondary-button" onClick={() => void copy()}>Copy {label}</button><span role="status">{message}</span></div>;
}

function LoadingPanel({ label }: { label: string }) { return <div className="loading-panel" role="status"><span className="loading-orb" />{label}</div>; }
function EmptyPanel({ title, detail }: { title: string; detail: string }) { return <div className="empty-panel"><span className="empty-panel-icon"><Icon name="file" /></span><div><strong>{title}</strong><span>{detail}</span></div></div>; }

function ApprovalPage({ config }: { config: ApprovalConfig | null }) {
  const [documents, setDocuments] = useState<DocumentSummary[]>([]);
  const [selectedDocument, setSelectedDocument] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("No task starts until you approve this action.");
  const [error, setError] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const toolId = config?.tool_id;
  const expectedDocument = toolId === "invoice_analyzer" ? "doc-invoice" : "doc-report";

  useEffect(() => {
    if (!config) return;
    let cancelled = false;
    void requestJson<components["schemas"]["DocumentListResponse"]>("/api/documents")
      .then((result) => {
        if (cancelled) return;
        const match = result.documents.filter((item) => item.id === expectedDocument);
        setDocuments(match);
        setSelectedDocument(match[0]?.id ?? "");
        if (!match.length) setError("The registered input is not available in the trusted document registry.");
      })
      .catch((reason: unknown) => { if (!cancelled) setError(errorFor(reason).message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [config, expectedDocument]);

  const approve = async () => {
    if (!config || !selectedDocument || busy) return;
    const csrf = csrfToken();
    if (!csrf) { setError("Your owner session has expired. Return to ACLAIS and sign in again."); return; }
    setBusy(true);
    setError(null);
    setMessage("Sending your explicit approval to ACLAIS…");
    try {
      const result = await requestJson<components["schemas"]["TaskRecord"]>("/api/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf, "X-Aclais-Approval-Context": config.approval_context },
        body: JSON.stringify({ schema_version: 1, tool_id: config.tool_id, selected_document_id: selectedDocument, launch_source_claim: config.launch_source_claim }),
      });
      sessionStorage.setItem("aclais:selectedTaskId", result.task_id);
      setMessage("Approval accepted. Opening the recorded task in your workspace.");
      window.location.assign("/owner");
    } catch (reason) {
      const failure = errorFor(reason);
      setError(failure.message);
      setMessage(failure.code === "TASK_BUSY" ? "Another task is already active." : "No task was launched.");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { headingRef.current?.focus(); }, []);
  const title = config ? taskName(config.tool_id) : "Approval unavailable";
  const registeredDocument = documents[0];

  return <div className="approval-frame">
    <header className="approval-topbar"><a className="brand" href="/owner"><BrandMark /><span>ACLAIS</span></a><div className="approval-context-label"><span className="context-dot" />OWNER APPROVAL</div></header>
    <main className="approval-content">
      <a className="back-link" href="/owner">← Back to workspace</a>
      <section className="approval-card">
        <div className="approval-hero-icon"><Icon name="shield" /></div>
        <div className="page-kicker">REVIEW BEFORE ANY ACTION</div>
        <h1 ref={headingRef} tabIndex={-1}>Review and approve</h1>
        <p className="approval-lead">The action is fixed by ACLAIS. Nothing starts when this page opens.</p>
        {!config && <ProtectionNotice message="This page was not issued by the trusted ACLAIS approval route." />}
        {config && <>
          <div className="approval-tool"><div className="task-tool-glyph"><Icon name="spark" /></div><div><span>REGISTERED TOOL</span><strong>{title}</strong></div></div>
          <div className="approval-source-grid">
            <div><span>Source claim</span><strong>{config.launch_source_claim === "document_tools" ? "Document Tools" : config.launch_source_claim}</strong><small>User supplied claim</small></div>
            <div><span>Observed Origin</span><strong>{config.observed_origin ?? "Not provided"}</strong><small>Header observation only</small></div>
            <div className="source-referrer"><span>Observed referrer</span><strong>{config.observed_referer ?? "Not provided"}</strong><small>Header observation only</small></div>
          </div>
          <div className="approval-section-head"><div><span className="section-kicker">TRUSTED INPUT</span><h2>Select the registered document</h2></div></div>
          <label className="approval-document-label" htmlFor="approval-document">Selected document</label>
          {loading ? <LoadingPanel label="Loading trusted document registry" /> : documents.length === 0 ? <EmptyPanel title="Registered input unavailable" detail="The controller did not return the input registered for this tool." /> : <div className="approval-document-select"><span className="document-icon"><Icon name="file" /></span><select id="approval-document" value={selectedDocument} onChange={(event) => setSelectedDocument(event.target.value)} aria-label="Selected document">{documents.map((item) => <option key={item.id} value={item.id}>{item.display_name}</option>)}</select><span className="document-select-detail">{registeredDocument?.media_type} · {registeredDocument ? bytes(registeredDocument.size_bytes) : ""}</span></div>}
          <div className="contract-card"><div className="contract-heading"><span className="contract-icon"><Icon name="shield" /></span><div><span className="section-kicker">ACTION CONTRACT</span><strong>Permissions ACLAIS will enforce</strong></div></div><ul><li>Read only the selected trusted document.</li><li>Publish one validated result in the ACLAIS output store.</li><li>Other documents and original-file changes are prohibited.</li><li>The caller cannot choose an executable, arguments, grants or filesystem paths.</li></ul></div>
          {error && <div className="approval-error" role="alert"><Icon name="alert" /><span>{error}</span></div>}
          <div className="approval-actions"><a className="secondary-button" href="/owner">Cancel</a><button className="primary-button approval-submit" onClick={() => void approve()} disabled={loading || busy || !selectedDocument}><span>{busy ? "Submitting approval…" : "Approve and open"}</span><Icon name="arrow" /></button></div>
          <p className="approval-status" role="status">{message}</p>
        </>}
      </section>
      <p className="approval-footer"><Icon name="shield" /> Approval belongs to the authenticated ACLAIS owner session.</p>
    </main>
  </div>;
}
