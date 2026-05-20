package localloop

import (
	"database/sql"
	"html/template"
	"net/http"
)

// dashboardRow is one row in the local flows table view.
type dashboardRow struct {
	TenantID       string
	FlowID         string
	CorrelationID  string
	EventCount     int
	FlowMerkleRoot string
	WindowClosedAt string
	ClosureReason  string
	SnapshotURI    string
}

// LocalDashboardLinks are browser-friendly origins shown on the dashboard for
// quick navigation (ingest, verifier, this page).
type LocalDashboardLinks struct {
	IngestURL    string
	VerifierURL  string
	DashboardURL string
}

const dashboardPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IntentProof local</title>
<style>
:root {
  --bg: #f6f7fb;
  --surface: #fff;
  --border: #e2e5ec;
  --text: #1a1d26;
  --muted: #5c6370;
  --accent: #2563eb;
  --accent-soft: #eff6ff;
  --open: #0d9488;
  --open-bg: #ccfbf1;
  --closed: #6b7280;
  --closed-bg: #f3f4f6;
  --shadow: 0 1px 3px rgba(0,0,0,.06);
  --radius: 10px;
}
* { box-sizing: border-box; }
body {
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
.top {
  background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
  color: #e8eef8;
  padding: 1.75rem 1.5rem 2rem;
}
.top h1 { margin: 0 0 0.35rem; font-size: 1.5rem; font-weight: 650; letter-spacing: -0.02em; }
.top p { margin: 0; opacity: 0.88; font-size: 0.95rem; }
.wrap { max-width: 1200px; margin: 0 auto; padding: 0 1rem 2.5rem; }
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1.1rem 1.25rem;
  margin-top: -1.25rem;
  position: relative;
}
.panel h2 { margin: 0 0 0.75rem; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.link-grid {
  display: grid;
  gap: 0.65rem 1.25rem;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  list-style: none;
  padding: 0;
  margin: 0;
}
.link-grid li { font-size: 0.9rem; }
.link-grid .label { display: block; font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.15rem; }
.link-grid a { color: var(--accent); font-weight: 500; text-decoration: none; word-break: break-all; }
.link-grid a:hover { text-decoration: underline; }
.flows-head { margin: 1.75rem 0 0.75rem; display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.5rem 1rem; }
.flows-head h2 { margin: 0; font-size: 1.15rem; font-weight: 650; }
.flows-head .hint { font-size: 0.85rem; color: var(--muted); }
.table-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  overflow: auto;
  max-width: 100%;
}
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; min-width: 720px; }
th, td { padding: 0.55rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: #f9fafc; font-weight: 600; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); white-space: nowrap; }
tbody tr:hover { background: var(--accent-soft); }
tbody tr:last-child td { border-bottom: none; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace; font-size: 0.8rem; }
.cell-id { max-width: 14rem; }
.cell-id code { word-break: break-all; }
.cell-root code { display: block; max-width: 18rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cell-snap code { display: block; max-width: 16rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pill {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 0.2rem 0.45rem;
  border-radius: 999px;
}
.pill-open { background: var(--open-bg); color: var(--open); }
.pill-closed { background: var(--closed-bg); color: var(--closed); }
.muted { color: var(--muted); }
.empty {
  text-align: center;
  padding: 2.5rem 1.5rem;
  background: var(--surface);
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  color: var(--muted);
}
.empty strong { color: var(--text); }
.err { color: #b91c1c; background: #fef2f2; border: 1px solid #fecaca; border-radius: var(--radius); padding: 1rem 1.1rem; margin-top: 1rem; }
.copy-row { display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; }
.copy-btn {
  font: inherit;
  font-size: 0.68rem;
  padding: 0.15rem 0.4rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: #fff;
  cursor: pointer;
  color: var(--muted);
}
.copy-btn:hover { border-color: var(--accent); color: var(--accent); }
footer { margin-top: 2rem; font-size: 0.8rem; color: var(--muted); text-align: center; }
</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <h1>IntentProof local</h1>
    <p>Materialized flows for tenant <code style="background:rgba(255,255,255,.12);padding:0.1rem 0.35rem;border-radius:4px">tnt_local</code> — newest first.</p>
  </div>
</header>
<div class="wrap">
{{if or .Links.IngestURL .Links.VerifierURL .Links.DashboardURL}}
<section class="panel">
  <h2>Endpoints</h2>
  <ul class="link-grid">
    {{if .Links.IngestURL}}<li><span class="label">Ingest</span><a href="{{.Links.IngestURL}}/v1/events">{{.Links.IngestURL}}/v1/events</a></li>{{end}}
    {{if .Links.VerifierURL}}<li><span class="label">Verify run (JSON)</span><a href="{{.Links.VerifierURL}}/v1/verify/run">{{.Links.VerifierURL}}/v1/verify/run</a></li>{{end}}
    {{if .Links.VerifierURL}}<li><span class="label">Verify bundle (tar)</span><a href="{{.Links.VerifierURL}}/v1/verify/bundle">{{.Links.VerifierURL}}/v1/verify/bundle</a></li>{{end}}
    {{if .Links.DashboardURL}}<li><span class="label">This dashboard</span><a href="{{.Links.DashboardURL}}/">{{.Links.DashboardURL}}/</a></li>{{end}}
  </ul>
</section>
{{end}}
{{if .Err}}
<p class="err">Could not load flows: {{.Err}}</p>
{{else}}
<div class="flows-head">
  <h2>Flows</h2>
  <span class="hint">Up to 100 rows. Open flows sort above closed.</span>
</div>
{{if .Rows}}
<div class="table-wrap">
<table>
<thead><tr>
<th>Status</th>
<th>Correlation</th>
<th>Flow</th>
<th>Events</th>
<th>Merkle root</th>
<th>Closed</th>
<th>Closure</th>
<th>Snapshot</th>
</tr></thead>
<tbody>
{{range .Rows}}
<tr>
<td>{{if eq .WindowClosedAt ""}}<span class="pill pill-open">Open</span>{{else}}<span class="pill pill-closed">Closed</span>{{end}}</td>
<td class="cell-id"><div class="copy-row"><code>{{.CorrelationID}}</code><button type="button" class="copy-btn" data-copy="{{.CorrelationID}}">Copy</button></div></td>
<td class="cell-id"><code>{{.FlowID}}</code></td>
<td>{{.EventCount}}</td>
<td class="cell-root" title="{{.FlowMerkleRoot}}"><code>{{.FlowMerkleRoot}}</code></td>
<td class="mono">{{.WindowClosedAt}}</td>
<td>{{.ClosureReason}}</td>
<td class="cell-snap" title="{{.SnapshotURI}}"><code>{{.SnapshotURI}}</code></td>
</tr>
{{end}}
</tbody></table>
</div>
{{else}}
<div class="empty">
  <p><strong>No flows yet.</strong></p>
  <p>POST execution events to the ingest URL above, then refresh this page.</p>
</div>
{{end}}
{{end}}
<footer>IntentProof local loop — Ctrl-C in the terminal stops all services.</footer>
</div>
<script>
document.querySelectorAll('.copy-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var t = btn.getAttribute('data-copy') || '';
    if (!t) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).then(function() {
        var prev = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function() { btn.textContent = prev; }, 1200);
      });
    }
  });
});
</script>
</body></html>
`

var dashboardTmpl = template.Must(template.New("dash").Parse(dashboardPage))

type dashboardView struct {
	Err   string
	Rows  []dashboardRow
	Links LocalDashboardLinks
}

// LocalDashboardHandler serves an HTML dashboard for flows in the local SQLite
// database (default :9789). Pass non-zero links so the page can deep-link to
// ingest and verifier endpoints.
func LocalDashboardHandler(db *sql.DB, links LocalDashboardLinks) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		view := dashboardView{Links: links}
		rows, err := db.Query(`
			SELECT tenant_id, flow_id, correlation_id,
				COALESCE(event_count, 0), COALESCE(flow_merkle_root, ''),
				COALESCE(window_closed_at, ''), COALESCE(closure_reason, ''),
				COALESCE(snapshot_uri, '')
			FROM flows
			WHERE tenant_id = ?
			ORDER BY (window_closed_at IS NULL) DESC, window_closed_at DESC, flow_id DESC
			LIMIT 100`, LocalTenantID)
		if err != nil {
			view.Err = err.Error()
		} else {
			defer rows.Close()
			for rows.Next() {
				var row dashboardRow
				if err := rows.Scan(&row.TenantID, &row.FlowID, &row.CorrelationID,
					&row.EventCount, &row.FlowMerkleRoot, &row.WindowClosedAt,
					&row.ClosureReason, &row.SnapshotURI); err != nil {
					view.Err = err.Error()
					view.Rows = nil
					break
				}
				view.Rows = append(view.Rows, row)
			}
			if err := rows.Err(); err != nil && view.Err == "" {
				view.Err = err.Error()
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = dashboardTmpl.Execute(w, view)
	})
	return mux
}
