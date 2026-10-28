import { useEffect, useState } from "react";

import type { components } from "./generated/api";

type HealthResponse = components["schemas"]["HealthResponse"];
type HealthCheck = components["schemas"]["HealthCheck"];

function isHealthCheck(value: unknown): value is HealthCheck {
  if (typeof value !== "object" || value === null) return false;
  const check = value as Record<string, unknown>;
  return (
    (check.id === "application_api" || check.id === "g1_protection") &&
    (check.status === "pass" || check.status === "fail" || check.status === "unknown") &&
    typeof check.summary === "string"
  );
}

function isHealthResponse(value: unknown): value is HealthResponse {
  if (typeof value !== "object" || value === null) return false;
  const health = value as Record<string, unknown>;
  return (
    health.schema_version === 1 &&
    (health.status === "ready" || health.status === "unavailable") &&
    typeof health.protection_ready === "boolean" &&
    Array.isArray(health.checks) &&
    health.checks.every(isHealthCheck)
  );
}

export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    async function loadHealth() {
      try {
        const response = await fetch("/api/health", {
          headers: { Accept: "application/json" },
          cache: "no-store",
          credentials: "same-origin",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("health request failed");
        const body: unknown = await response.json();
        if (!isHealthResponse(body)) throw new Error("health response did not match its schema");
        setHealth(body);
      } catch {
        if (!controller.signal.aborted) setFailed(true);
      }
    }

    void loadHealth();
    return () => controller.abort();
  }, []);

  const applicationCheck = health?.checks.find((check) => check.id === "application_api");
  const protectionCheck = health?.checks.find((check) => check.id === "g1_protection");

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="wordmark" href="/" aria-label="ACLAIS local foundation home">
          <span className="wordmark-mark" aria-hidden="true">A</span>
          <span>ACLAIS</span>
        </a>
        <span className="environment-label">LOCAL DEVELOPMENT</span>
      </header>

      <section className="status-panel" aria-labelledby="page-title">
        <div className="panel-kicker">PROJECT FOUNDATION</div>
        <h1 id="page-title">A clear starting point.</h1>
        <p className="lead">
          The local API and dashboard shell are connected. Worker isolation and protection
          checks will appear here only when implemented and verified.
        </p>

        <div className="status-card" aria-live="polite">
          <span
            className={`status-indicator ${health?.protection_ready ? "is-ready" : "is-pending"}`}
            aria-hidden="true"
          />
          <div className="status-copy">
            <p className="status-title">
              {failed
                ? "API unavailable"
                : health?.protection_ready
                  ? "Protection ready"
                  : health
                    ? "Protection not ready"
                    : "Checking local API"}
            </p>
            <p className="status-detail">
              {failed
                ? "Start the backend by following RUNBOOK.md."
                : applicationCheck?.summary ?? "Waiting for the local health response."}
            </p>
          </div>
          <span className="status-tag">
            {failed ? "OFFLINE" : health?.status === "ready" ? "READY" : "NOT READY"}
          </span>
        </div>

        {health && protectionCheck && (
          <div className="readiness-note">
            <span className="note-label">G1 protection</span>
            <span>{protectionCheck.summary}</span>
          </div>
        )}
      </section>

      <footer className="footer">
        <span>Development foundation · A1</span>
        <span>Loopback only</span>
      </footer>
    </main>
  );
}
