# SentinelX front end — unslopped

Rebuilt November 6, 2026 from the October 17 screenshots in `../shots/`
(the original Vite front end was deleted that day, so the screenshots are
the spec). Same 8 screens, same content and order, same routes — only the
craft changed, following the unslop skill by Damir Sokolovsky
([@heydamir](https://x.com/heydamir), CC BY 4.0).

## Direction

- Product: probes a site you own and reports every finding with raw proof
  and a one-click curl reproducer
- Character: exact, quiet, forensic
- World: a night-shift SOC desk — dark instrument panels, log lines,
  monochrome readouts
- Moments: the live scan terminal with real log lines, and the severity
  bars — the only place colour gets rich, each hue meaning a severity
- Signature: the curl reproducer as a keycap-style "Copy curl" on every
  finding, mono figures (CVSS, counts) everywhere

## What changed

- Dark ink theme (`#0b0d14` page, `#11141c` cards, `#1a1e28` raised):
  the purple-to-blue gradients, gradient headline text, gradient logo
  tile, glowing buttons and lavender pills are all gone
- Flat shield mark + wordmark, one line-icon set (16px, 1.5 stroke),
  no emoji anywhere
- Sentence case throughout, weights 400/500, Inter + IBM Plex Mono,
  tabular figures, one format for numbers
- Stat cards are numbers only (label + figure + comparison), no icons
  or sparklines; severity shown as a small dot + quiet mono text
- Overview data corrected: the original shot showed 0 open findings
  next to 7 findings — now 3 total scans, 2 active, 1 completed,
  7 open findings, posture 82/100 from the page's own weights
  (Critical −25, High −10, Medium −4, Low −1)
- Landing hero is the product itself: a coded findings preview rising
  beside the headline, no generated image
- Mobile: top bar wraps to two rows, hero stacks, no horizontal overflow
  at 375px

## Files

- `index.html` landing, `login.html` sign in, `dashboard.html` new scan,
  `scan.html` live scan, `findings.html` findings, `history.html` scan
  history, `overview.html` security overview, `settings.html` settings,
  `shots.html` gallery of the original captures (the before record)
- `assets/style.css` — the whole design system, one file
- `assets/app.js` — search filtering, copy buttons, form navigation
- `assets/favicon.svg` — flat shield mark
- `DESIGN.md` — the per-page content spec the build followed

## How to view

Static only — no backend. Open `index.html` in a browser, or serve the
folder (`python3 -m http.server`) and open `http://localhost:8000/`.
Buttons navigate between the screens and search filters client-side;
no scan actually runs, because the FastAPI backend was deleted with
the old front end. The HTML report the CLI generates
(`sentinelx/reports/reports.py`) uses the same design system, so new
scan reports match these screens.

## Verified

- All 9 pages parse clean, every class used exists in `style.css`,
  every internal link and image resolves
- Rendered in headless Chrome at 1440px and 375px and inspected:
  no overflow, no clipping, no console errors
- Search filter tested live: "x-frame" → 1 row, "misconfiguration" →
  5 rows; sign-in with filled fields → overview; Save settings →
  "Saved"
- Report template regenerated from `sentinelx-report.json`: 14 findings,
  all rendering, no emoji, no pills, no uppercase labels
