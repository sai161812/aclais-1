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

Approval: tool name and source claim; selected document picker; “Can read selected document” and “Can create a separate result”; prohibited actions summarized clearly. Primary “Open securely,” secondary Cancel. Do not bury important permissions inside tooltips. Only the trusted ACLAIS page owns approval.

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

## Visual acceptance
Capture Workspace, Approval, Running, Incident verified, Verification incomplete, and Disconnected at 1366×768 and 1920×1080. Inspect for clipping, illegible glass, inconsistent padding, excessive empty space, broken icons, focus loss and fake placeholder data. Test keyboard path: select tool → approve → inspect result → open/close incident. Capture at least one reduced-motion run. Production bundle must have no runtime font/CDN requests.

Document Tools should share typography quality but use a distinct simpler neutral utility brand. The receiver can stay a clean text inspector; do not spend UI time there before ACLAIS is finished.
