# SentinelX front-end rebuild — content spec

Rebuild the 8 screens from `../shots/*.png` (the deleted Vite front end, Oct 17)
as static pages in this folder, using ONLY classes from `assets/style.css`.
No new CSS, no inline styles, no gradients, no glows, no emoji, no pills,
no uppercase tracked labels. Sentence case everywhere. Weights 400/500
(600 only for the wordmark). Copy below is exact — do not invent features,
claims or data beyond what is listed here.

Shared shell on every page: `.topbar` with brand (flat shield SVG +
"SentinelX"), nav Home / Overview / Scan / History / Settings, right side
Shots / Logout. Active nav item gets `.active`. Footer on every page:
"SentinelX — a real, working vulnerability scanner." left, "Only scan
targets you own or are authorised to test." right.
Icons: inline SVG, lucide-style, 16px, stroke 1.5, colour from the text role.
Shield mark SVG: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
stroke-width="1.5"><path d="M12 2l8 3v6c0 5-3.5 9.3-8 11-4.5-1.7-8-6-8-11V5l8-3z"/><path d="M9 12l2 2 4-4"/></svg>`.
Other icons: home, layout-grid (overview), target/crosshair (scan),
history/clock-rotate (history), settings gear, camera (shots), log-out,
search, chevron-right, rotate-ccw (re-run), trash, download, zap, check,
alert-triangle, activity, key, gauge. Draw them as simple lucide-style
line SVGs; if unsure of a path, use a plain circle or chevron instead of
guessing a complex glyph.

Demo data (plausible, from the shots — keep it consistent across pages):
- Target: `http://127.0.0.1:5055`
- History scans: 7 findings, Oct 17, 2026, 4:56:57 AM · 22 findings,
  Oct 17, 2026, 4:48:56 AM · 18 findings, Oct 17, 2026, 4:44:49 AM
- The 7-finding scan: 0 critical, 0 high, 4 medium, 2 low, 1 info.
  Findings list:
  1. Security Misconfiguration — missing-header:strict-transport-security —
     GET http://127.0.0.1:5055 · CVSS 4.8 — Medium
  2. Security Misconfiguration — missing-header:content-security-policy —
     GET http://127.0.0.1:5055 · CVSS 4.2 — Medium
  3. Security Misconfiguration — missing-header:x-frame-options —
     GET http://127.0.0.1:5055 · CVSS 4.3 — Medium
  4. Security Misconfiguration — missing-header:x-content-type-options —
     GET http://127.0.0.1:5055 · CVSS 3.1 — Low
  5. Security Misconfiguration — missing-header:referrer-policy —
     GET http://127.0.0.1:5055 · CVSS 3.7 — Low
  6. Information Disclosure — tech:flask — GET http://127.0.0.1:5055 —
     Info (no CVSS shown)
  7. Information Disclosure — server version disclosure —
     GET http://127.0.0.1:5055 — Info (no CVSS shown)
  The 7th row is derived from the shot's visible 6th row and the 0/0/4/2/1
  counts; keep it clearly an info-level disclosure, nothing stronger.
- Overview: 3 total scans, 2 active now, 0 completed, 0 open findings is
  WRONG in the original shot (it contradicts the 7 findings). Use instead:
  3 total scans, 2 active now, 1 completed, 7 open findings. Security
  posture 82/100, weighted: Critical −25, High −10, Medium −4, Low −1
  (100 − 4×4 − 2×1 = 82). Severity bars use the 0/0/4/2/1 counts.
- Landing stats: 19 detection modules, 31 encoding transforms,
  25 WAF fingerprints, 0 false positives — "on hardened reference target".

## index.html — Landing
- `.wrap-wide`, `.hero`: left — h1 "Find web vulnerabilities before
  attackers do." (one line break after "vulnerabilities" on desktop is
  fine), sub "SentinelX is a real, working vulnerability scanner.
  Nineteen modules probe every endpoint, and each finding carries raw
  evidence, CVSS scoring, and a one-click reproducer.", actions:
  primary "Start a scan" → dashboard.html, secondary "View history" →
  history.html.
- Right — `.preview` of the findings screen (the moment): head
  "Findings (7)" + "View all →" link to findings.html; three preview
  rows (findings 1, 2 and 4 above) with severity dot + title + mono
  subtype + meta "GET http://127.0.0.1:5055 · CVSS 4.8".
- Below — `.hero-stats` stat cards (label first, figure second):
  "Detection modules" 19 · "Encoding transforms" 31 ·
  "WAF fingerprints" 25 · "False positives" 0 with label
  "False positives" and a second line "on hardened reference target"
  in 13px muted text under the figure. No icons, no sparklines.

## login.html — Sign in
- `.auth` card: `.mark` shield SVG, h1 "Sign in", sub "Sign in to run
  scans and review findings." Form: Email label, input placeholder
  "you@example.com", type email; Password label, input placeholder
  "••••••••", type password. Primary block button "Sign in" (form
  submit goes to overview.html). Foot: "No account? Register" (Register
  is a link, href="#") then a second line "Back home" link to index.html.
  No greeting headline, no gradient border, no gradient button.

## dashboard.html — New scan
- `.page-head`: h1 "New scan", sub "Configure and launch a full
  vulnerability scan."
- `.card`: label "Target URL", input mono value
  "http://127.0.0.1:5055". `.form-grid`: Concurrency 30, Rate (req/s) 10,
  Crawl depth 2 (number inputs, labels sentence case).
- `.consent`: checkbox + "I confirm I own this target or have explicit
  written permission to test." ("I confirm I own this target" in bold
  text, rest secondary).
- Primary button "Start scan" (submit → scan.html).
- Section below: `.section-title` "Recent scans", `.row-list` with the
  3 history rows: target mono + meta "7 findings · Oct 17, 2026,
  4:56:57 AM" etc., right side `.status` text "Running" with
  `.dot-live` or "Completed" plain, plus chevron link to findings.html.
  Status is quiet mono text with a dot, never a pill.

## scan.html — Live scan
- `.page-head-row`: h1 "Live scan" + sub "Scanning
  http://127.0.0.1:5055" (target in mono), actions: secondary "Cancel"
  (danger style, → dashboard.html), primary "Findings (0)" →
  findings.html.
- `.stat-row` 4 stats: Findings 0, Critical 0, High 0, Status "live"
  (the figure is the word "live" in 32px, with a `.dot-live` before the
  label "Status"). Labels: "Findings", "Critical", "High", "Status".
- `.terminal` with `.terminal-head` (three grey dots + "scan output —
  live") and lines (static HTML, one per line):
  `connecting to scan stream…`
  `crawler: 14 endpoints found`
  `sqli: probing GET /search?q=`
  `xss: probing GET /search?q=`
  `ssrf: probing POST /product/stock`
  `headers: 5 misconfigurations found`
  then a green `.cursor` block. The "Findings (0)" button and the
  "Findings" stat stay 0 on this static page.
- Section: `.section-title` "Findings feed", `.card` with `.empty`:
  "No findings yet — they stream in live as modules confirm them."

## findings.html — Findings
- `.page-head-row`: h1 "Findings (7)", actions: three secondary buttons
  "JSON", "HTML", "SARIF" each with a download icon (href="#").
- `.stat-row` 5 stats — use a 5-column row: add inline style? No.
  Use `.stat-row` but with `grid-template-columns: repeat(5, 1fr)` via a
  `style` attribute on that one element ONLY (the system has no 5-col
  variant; this is the single allowed exception). Stats: Critical 0,
  High 0, Medium 4, Low 2, Info 1, each with its severity dot before
  the label.
- Search input with placeholder "Search findings", `data-filter`
  attribute, filters the rows client-side (see app.js).
- `.row-list` of the 7 findings: left severity (`.sev sev-medium` with
  dot + "Medium"), title + mono subtype, meta "GET
  http://127.0.0.1:5055 · CVSS 4.8"; right chevron. Each row is a link
  to "#" (finding detail does not exist in this static build).

## history.html — Scan history
- `.page-head`: h1 "Scan history", no subhead.
- Search input placeholder "Search by target", `data-filter`.
- `.row-list` of the 3 history rows: target mono + meta "7 findings ·
  Oct 17, 2026, 4:56:57 AM"; right side: chevron link, re-run icon
  button, delete icon button. No dead space: nothing after the list
  except the footer.

## overview.html — Security overview
- `.page-head-row`: h1 "Security overview", sub "What's happening with
  your security right now.", action primary "New scan" → dashboard.html.
- `.stat-row`: Total scans 3, Active now 2, Completed 1, Open findings 7.
- Two-column grid (use `.card` pair inside a div with
  `style="display:grid;grid-template-columns:1fr 2fr;gap:24px"` — the
  single allowed inline-style exception on this page): left card
  "Security posture" — donut SVG ring (positive green, 82%) with
  "82" big + "/ 100" muted, note "Weighted by severity across all open
  findings. Critical −25, High −10, Medium −4, Low −1." Right card
  "Findings by severity" — `.sev-bar-row` × 5: Critical 0, High 0,
  Medium 4, Low 2, Info 1, bars filled proportionally (4 = full width
  of the largest, 2 = half, 0 = empty track).
- Second row, two equal `.card`s: "Recent scans" (3 history rows,
  compact, with status text + chevron, "View all →" to history.html)
  and "Latest findings" (top 3 findings rows, "View all →" to
  findings.html). Card head uses `.card-head` with h2 + `.more` link.

## settings.html — Settings
- `.page-head`: h1 "Settings", no subhead.
- Card 1: h2 "AI enhancement keys", note "Read from
  <span class=keycap>OPENAI_API_KEY</span> /
  <span class=keycap>ANTHROPIC_API_KEY</span> on the server." Fields:
  "OpenAI key" input mono placeholder "sk-…", "Anthropic key" input
  mono placeholder "sk-ant-…".
- Card 2: h2 "Scan defaults", `.form-grid`: Concurrency 30, Rate /s 10,
  Depth 2. Primary button "Save settings" (submit → stays, button text
  becomes "Saved" via app.js).
- Cards separated by 24px (use `.section` wrappers).

## shots.html — Shots
- `.page-head`: h1 "Shots", sub "Original captures of the first front
  end, October 17, 2026 — kept as the before record for this rebuild."
- `.shot-grid` with one figure per original capture in `../shots/`:
  landing-1440.png, login-1440.png, dashboard-1440.png,
  live-scan-1440.png, findings-1440.png, history-1440.png,
  overview-1440.png, settings-1440.png. Caption: screen name + mono
  file name. Images referenced as `../shots/<file>` (relative path
  out of this folder). Alt text: "Original capture of the <name> screen".

## app.js (assets/app.js)
- `data-filter` inputs filter sibling `.row-list .row` elements by
  text, case-insensitive; hide non-matches with `display:none`.
- Buttons with `data-copy` copy the previous sibling's text via
  navigator.clipboard and change label to "Copied" for 1.5s.
- Forms: prevent default; login form → overview.html; new-scan form →
  scan.html; settings form → set the submit button text to "Saved"
  for 2s.
- No other behaviour. No animations, no entrance effects.
