# Visual and interaction specification

## Direction
ACLAIS should feel like a polished desktop security application: restrained Apple-inspired glass, crisp typography, clear hierarchy, generous spacing, and high-contrast evidence. Do not copy Apple branding or imply affiliation. Glass is a surface treatment, not a reason to make text unreadable.

Use light graphite text on pearl surfaces, cool blue accent and subtle cyan ambient background. Avoid neon hacker green, animated code rain, giant glowing shields, crowded KPI grids, cartoon illustrations and marketing slogans.

## Tokens
CSS custom properties: background #F3F5F9; text #172033; muted #566279; accent #246BFD; success #137A54; warning #996300; danger #BD3248. Base spacing scale 4,8,12,16,24,32,48 px. Main panel radius 24px; nested card 16px; controls 12px. Panel background rgba(255,255,255,.78), white hairline border, backdrop blur 20px, shadow 0 12px 40px rgba(26,42,72,.08). Use a solid near-white fallback when backdrop-filter is unsupported or transparency reduced.

Use system sans stack: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif. Windows must look good in Segoe UI; do not depend on unavailable SF Pro files. Body 14–16px, metadata at least 12px, title 28–32px, weight 600. Monospace only for hashes/IDs. Contrast-check actual composited surfaces; ordinary text should meet 4.5:1. Color never carries status alone.

## Layout
At desktop widths: 220px navigation rail, flexible main panel, optional 360px incident drawer. At 1366×768 collapse low-priority metadata and use a drawer overlay rather than shrinking main text. Main content max width about 1440px. No horizontal page scroll.

Rail: ACLAIS wordmark, Workspace, Activity, Protection status. No Demo menu. Top bar: page title, trustworthy health status, small connection indicator. A failed backend must show disconnected/protection unavailable rather than last-known green status.

Workspace: document list with file icon, name, type, protected state and last verified information. Primary task area shows current tool, approved task and progress based on actual events. Keep default dashboard quiet; do not populate it with invented attack counts.

Approval: tool name and source claim; trusted selected-document picker; explicit contract summary showing read access to only that document and one validated result in ACLAIS; clearly list that other documents, original-file changes, caller executables, arguments, grants and paths are prohibited. Show normalized observed Origin/referrer separately from the user-supplied source claim. Primary “Approve and open,” secondary Cancel. Do not bury important permissions inside tooltips. Only the trusted ACLAIS page owns approval.

Task view: approved action, selected file, result preview, concise factual timeline. On incident, show a calm notification with “View details.” Do not erase useful output; mark it as originating from a stopped tool.

Incident drawer: what happened; why it was outside the contract; action ACLAIS took; verification result. Advanced evidence expands to source categories, task/run IDs, operation, exact target ID, broker result, process identity and hashes. Show worker-reported errors separately from controller/verifier records.

## State-specific copy
- Healthy: “Workspace protection ready.” Only after preflight.
- Preparing: “Preparing a restricted workspace.”
- Running: “Formatting report” / “Extracting invoice details.”
- Violation pending verification: “Unauthorized action denied. Verifying your files…”
- Verified integrity: “Protected originals unchanged.”
- Confidentiality: “Access to Personnel_Private.csv was denied.”
- Receiver healthy and empty: “No seeded confidential payload received for this run.”
- Receiver down: “Receiver verification unavailable.”
- Failure: “Protection unavailable” or “Verification incomplete,” with recovery action.

Never claim “0 bytes leaked,” “AI neutralized threat,” “100% protected,” or “all attacks blocked.” No prefilled blocked-event feeds.

## Interaction and implementation
Motion 160–220ms opacity/transform, honor prefers-reduced-motion. No security action waits for animation. Loading skeletons only while actual requests are pending. Buttons have hover/focus/disabled/loading states and descriptive labels. Trap focus in modal/drawer, Escape closes where safe, return focus to trigger, visible focus ring. Announce incident politely through aria-live; avoid repeated alerts every poll. Use semantic headings and labels.

Sanitize or escape untrusted output; prefer plain-text Markdown preview for v1. Never dangerouslySetInnerHTML on tool output. Limit rendered event lengths. Copy IDs/hashes with explicit feedback; hide secrets entirely. Dates localize to Asia/Kolkata.

## Screen-to-API mapping
The UI is connected to the strict response models in `02_SHARED_CONTRACTS.md`. Show loading only while a request is pending; show explicit empty, disconnected, unavailable and verification-incomplete states from actual responses. Do not fill a screen with sample incidents or last-known green values.

| Screen/state | API requests and actions | Rendered data and rules |
|---|---|---|
| Workspace initial load | `GET /api/health`, `GET /api/documents`, `GET /api/tasks?limit=20` | Health controls the protection indicator. Documents come from `DocumentListResponse`; recent task cards come from `TaskSummary`. A network/health failure is disconnected or protection unavailable, never cached healthy. |
| Activity | `GET /api/tasks?limit=50`; on selection `GET /api/tasks/{task_id}` | Sort/order is server-provided newest first. Use `TaskSummary` fields for the list and `TaskDetailResponse` for the selected task. No invented counts. |
| Approval | Authenticated top-level, side-effect-free ACLAIS `GET /approve?tool_id=...&launch_source_claim=document_tools`; then `GET /api/documents`; on explicit approval `POST /api/tasks` with `schema_version`, `tool_id`, `selected_document_id`, and `launch_source_claim`, `X-Aclais-Approval-Context`, CSRF header and exact Origin | Show the source claim separately from normalized observed Origin/referrer headers, which are not verified provenance. Approval fields come from the fixed route claim and `DocumentListResponse`. No task is created on page load or cancel. Only a successful explicit `POST` may launch; a 409/503 displays the actual conflict or preflight reason. No executable path or argv is accepted. |
| Running task | `GET /api/tasks/{id}` and `GET /api/tasks/{id}/events?after_seq=N`, every 500 ms while active | Use persisted status, output metadata and ordered `Event` values. Advance `after_seq` only to the returned `last_seq`; do not duplicate or synthesize events. |
| Completed task/result | `GET /api/tasks/{id}`, then `GET /api/outputs/{output_id}` for an available output | Render inert text/JSON only. The output is available only after journal/file verification. Display the actual task terminal state and output hash. |
| Incident drawer | `GET /api/tasks/{id}`, `GET /api/tasks/{id}/events?after_seq=N`, `GET /api/tasks/{id}/evidence` | Distinguish broker/controller/verifier records from `worker_reported`. Verification text comes only from `Incident` and `EvidenceReport` statuses. A pending/unknown/fail report never becomes green success. |
| Cancel action | `POST /api/tasks/{id}/cancel` with owner session, CSRF header and exact ACLAIS Origin; refresh task/events afterward | Show the returned terminal/current status. A cancel cannot overwrite an already committed policy, timeout, shutdown or terminal cause. |
| Disconnected / protection unavailable | `GET /api/health` failure or response with unavailable preflight check | Remove any green protection state and show a useful recorded check/error. Retry according to current UI polling state; never infer that no incident or no leakage occurred. |

Keep transport connectivity separate from protection readiness: a failed health request is **Disconnected**, while a reachable health response with a failed protection preflight is **Protection unavailable**. While an incident's evidence record is `pending`, label verification **Verification pending**; `unknown`, `fail`, and incomplete evidence remain non-success states. A reachable service with pending G1 gates is connected, but the workspace protection state remains pending. Active-task polling uses the event cursor only while connected; reconnect performs a persisted task/event refresh and merges by sequence without duplicates.

Render output bytes only as bounded inert text. Do not interpret markup, links, image tags, or scripts in worker output. A refresh uses backend task summaries and persisted events; an empty database remains an explicit empty state.

All owner API calls go to the ACLAIS origin only. Document Tools runs at `http://localhost:8766`, ACLAIS at `http://127.0.0.1:8765`, and the server-to-server receiver at `http://[::1]:8767`; the browser must not attach the ACLAIS host-only cookie to either other component. The cross-host approval link is an authenticated safe top-level GET; only an explicit ACLAIS mutation with the owner cookie, CSRF header, signed approval context and exact Origin can start a task.

Serve the built owner application and static assets from the authenticated ACLAIS origin, with a same-origin content policy and no-store approval HTML. Inject the signed approval context only into the root element's data attribute; page load remains side-effect-free. Resolve the bundle from an explicit project/install location rather than the shell working directory. The Vite editing preview uses the distinct `127.0.0.2` loopback host and has no owner API proxy; it must never receive the session cookie for `127.0.0.1`. A preview is not connected dashboard evidence.

## Visual acceptance
Capture Workspace, Approval, Running, Incident verified, Verification incomplete, and Disconnected at 1366×768 and 1920×1080. Inspect for clipping, illegible glass, inconsistent padding, excessive empty space, broken icons, focus loss and fake placeholder data. Test keyboard path: select tool → approve → inspect result → open/close incident. Capture at least one reduced-motion run. Production bundle must have no runtime font/CDN requests.

Document Tools should share typography quality but use a distinct simpler neutral utility brand. The receiver can stay a clean text inspector; do not spend UI time there before ACLAIS is finished.


G1 records live-backend pending/incomplete states separately from isolated typed UI fixtures for verified-receiver and containment-failure presentation. Fixture screenshots visibly state that no enforcement or receiver evidence is being shown. Production status remains backend-derived. Only terminated containment plus passing integrity and confidentiality displays "Protected originals unchanged"; a controller that no longer accepts work must make protection unavailable. Advanced evidence supports copying task/source identifiers with explicit feedback; no output HTML or Markdown is interpreted as active content.
