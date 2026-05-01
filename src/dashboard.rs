use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use tracing::{debug, error, info, warn};

use crate::config::DashboardConfig;
use crate::telemetry::DEFAULT_QUERY_WINDOW_HOURS;
use crate::telemetry_store::TelemetryStore;

#[derive(Clone)]
pub struct DashboardState {
    store: Arc<TelemetryStore>,
}

pub fn dashboard_router(store: Arc<TelemetryStore>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/usage/day", get(usage_day))
        .route("/api/tools/day", get(tools_day))
        .route("/api/errors/day", get(errors_day))
        .route("/api/timeline/day", get(timeline_day))
        .with_state(DashboardState { store })
}

pub async fn serve_dashboard(
    config: DashboardConfig,
    store: Arc<TelemetryStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr = config.listen_addr.parse::<SocketAddr>()?;
    if !listen_addr.ip().is_loopback() {
        warn!(
            listen_addr = %config.listen_addr,
            "Refusing to start dashboard on non-loopback address"
        );
        return Err("dashboard listen address must be loopback-only".into());
    }

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(listen_addr = %listen_addr, "Dashboard server started");
    axum::serve(listener, dashboard_router(store)).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    debug!("Serving dashboard HTML");
    Html(DASHBOARD_HTML)
}

async fn usage_day(State(state): State<DashboardState>) -> Response {
    let started = Instant::now();
    debug!("Handling dashboard usage endpoint");
    if let Err(error) = state.store.purge_expired().await {
        error!(endpoint = "/api/usage/day", error = %error, "Failed to purge telemetry before usage query");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to purge telemetry",
        )
            .into_response();
    }

    match state
        .store
        .usage_dashboard(DEFAULT_QUERY_WINDOW_HOURS)
        .await
    {
        Ok(payload) => {
            debug!(
                endpoint = "/api/usage/day",
                elapsed_ms = started.elapsed().as_millis(),
                model_rows = payload.by_model.len(),
                upstream_rows = payload.by_upstream.len(),
                "Dashboard usage endpoint completed"
            );
            Json(payload).into_response()
        }
        Err(error) => {
            error!(endpoint = "/api/usage/day", error = %error, "Dashboard usage query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "usage query failed").into_response()
        }
    }
}

async fn tools_day(State(state): State<DashboardState>) -> Response {
    let started = Instant::now();
    debug!("Handling dashboard tools endpoint");
    if let Err(error) = state.store.purge_expired().await {
        error!(endpoint = "/api/tools/day", error = %error, "Failed to purge telemetry before tools query");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to purge telemetry",
        )
            .into_response();
    }

    match state
        .store
        .tool_history_dashboard(DEFAULT_QUERY_WINDOW_HOURS, 200)
        .await
    {
        Ok(payload) => {
            debug!(
                endpoint = "/api/tools/day",
                elapsed_ms = started.elapsed().as_millis(),
                event_count = payload.events.len(),
                "Dashboard tools endpoint completed"
            );
            Json(payload).into_response()
        }
        Err(error) => {
            error!(endpoint = "/api/tools/day", error = %error, "Dashboard tools query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "tools query failed").into_response()
        }
    }
}

async fn errors_day(State(state): State<DashboardState>) -> Response {
    let started = Instant::now();
    debug!("Handling dashboard errors endpoint");
    if let Err(error) = state.store.purge_expired().await {
        error!(endpoint = "/api/errors/day", error = %error, "Failed to purge telemetry before errors query");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to purge telemetry",
        )
            .into_response();
    }

    match state
        .store
        .error_dashboard(DEFAULT_QUERY_WINDOW_HOURS, 100)
        .await
    {
        Ok(payload) => {
            debug!(
                endpoint = "/api/errors/day",
                elapsed_ms = started.elapsed().as_millis(),
                error_count = payload.errors.len(),
                "Dashboard errors endpoint completed"
            );
            Json(payload).into_response()
        }
        Err(error) => {
            error!(endpoint = "/api/errors/day", error = %error, "Dashboard errors query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "errors query failed").into_response()
        }
    }
}

async fn timeline_day(State(state): State<DashboardState>) -> Response {
    let started = Instant::now();
    debug!("Handling dashboard timeline endpoint");
    if let Err(error) = state.store.purge_expired().await {
        error!(endpoint = "/api/timeline/day", error = %error, "Failed to purge telemetry before timeline query");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to purge telemetry",
        )
            .into_response();
    }

    match state
        .store
        .request_timeline_dashboard(DEFAULT_QUERY_WINDOW_HOURS, 100)
        .await
    {
        Ok(payload) => {
            debug!(
                endpoint = "/api/timeline/day",
                elapsed_ms = started.elapsed().as_millis(),
                event_count = payload.events.len(),
                "Dashboard timeline endpoint completed"
            );
            Json(payload).into_response()
        }
        Err(error) => {
            error!(endpoint = "/api/timeline/day", error = %error, "Dashboard timeline query failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "timeline query failed").into_response()
        }
    }
}

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Proxy Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #fafafa;
      --panel: #ffffff;
      --panel-subtle: #f8fafc;
      --text: #09090b;
      --muted: #71717a;
      --line: #e4e4e7;
      --line-strong: #d4d4d8;
      --accent: #18181b;
      --accent-soft: #f4f4f5;
      --warn: #dc2626;
      --warn-soft: #fef2f2;
      --ok: #047857;
      --ok-soft: #ecfdf5;
      --shadow: 0 1px 2px rgba(24, 24, 27, 0.04);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
      min-height: 100vh;
    }
    header {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
      padding: 26px 32px 18px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.86);
      backdrop-filter: blur(10px);
    }
    h1 { margin: 0; font-size: 22px; font-weight: 720; line-height: 1.2; }
    .muted { color: var(--muted); font-size: 13px; }
    #updated {
      padding: 7px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      box-shadow: var(--shadow);
      white-space: nowrap;
    }
    main {
      display: grid;
      gap: 16px;
      padding: 22px 32px 32px;
      max-width: 1480px;
      margin: 0 auto;
      width: 100%;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 10px;
    }
    .stat, section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .stat {
      padding: 14px 15px;
      min-height: 88px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .label { color: var(--muted); font-size: 12px; font-weight: 600; }
    .value { margin-top: 10px; font-size: 27px; font-weight: 760; line-height: 1.05; letter-spacing: 0; }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    section { overflow: hidden; }
    .fold {
      max-width: none;
    }
    .fold > summary {
      display: flex;
      align-items: center;
      gap: 8px;
      min-height: 48px;
      padding: 13px 16px;
      border-bottom: 1px solid var(--line);
      color: var(--text);
      font-size: 14px;
      font-weight: 650;
      cursor: pointer;
      list-style: none;
      outline: none;
      user-select: none;
    }
    .fold:not([open]) > summary {
      border-bottom: 0;
    }
    .fold > summary:hover {
      background: var(--panel-subtle);
    }
    .fold > summary:focus-visible {
      box-shadow: inset 0 0 0 2px var(--accent);
    }
    .fold > summary::-webkit-details-marker {
      display: none;
    }
    .fold > summary::before {
      content: "";
      display: inline-block;
      width: 7px;
      height: 7px;
      border-right: 1.5px solid var(--muted);
      border-bottom: 1.5px solid var(--muted);
      transform: rotate(-45deg);
      transition: transform 120ms ease;
    }
    .fold[open] > summary::before {
      transform: rotate(45deg);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    thead {
      background: var(--panel-subtle);
    }
    th, td {
      padding: 10px 16px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      height: 38px;
    }
    tbody tr:hover {
      background: #fcfcfd;
    }
    tr:last-child td { border-bottom: 0; }
    .right { text-align: right; }
    .status, .error, .badge {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 12px;
      font-weight: 600;
      line-height: 1.2;
    }
    .error {
      border-color: #fecaca;
      background: var(--warn-soft);
      color: var(--warn);
    }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    details { max-width: 520px; }
    summary { cursor: pointer; color: var(--accent); font-weight: 650; }
    td > details {
      margin: 0 0 6px;
    }
    td > details > summary {
      display: inline-flex;
      padding: 3px 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      color: var(--accent);
      font-size: 12px;
    }
    td > details > summary:hover {
      background: var(--accent-soft);
    }
    pre {
      max-height: 220px;
      overflow: auto;
      margin: 8px 0 0;
      padding: 11px;
      background: #f8fafc;
      border: 1px solid var(--line);
      border-radius: 6px;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      line-height: 1.35;
    }
    @media (max-width: 900px) {
      header { align-items: start; flex-direction: column; padding: 20px; }
      main { padding: 18px; }
      .stats, .grid { grid-template-columns: 1fr; }
      .value { font-size: 24px; }
      th, td { padding: 10px 12px; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>AI Proxy Dashboard</h1>
      <div class="muted">Last 24 hours</div>
    </div>
    <div id="updated" class="muted">Loading</div>
  </header>
  <main>
    <div class="stats">
      <div class="stat"><div class="label">Total tokens</div><div id="totalTokens" class="value">0</div></div>
      <div class="stat"><div class="label">Input tokens</div><div id="inputTokens" class="value">0</div></div>
      <div class="stat"><div class="label">Output tokens</div><div id="outputTokens" class="value">0</div></div>
      <div class="stat"><div class="label">Requests</div><div id="requests" class="value">0</div></div>
      <div class="stat"><div class="label">Errors</div><div id="errors" class="value">0</div></div>
      <div class="stat"><div class="label">Auxiliary Errors</div><div id="auxiliaryErrors" class="value">0</div></div>
    </div>
    <div class="grid">
      <section>
        <details class="fold" open>
        <summary>Models</summary>
        <table>
          <thead><tr><th>Model</th><th class="right">Input</th><th class="right">Output</th><th class="right">Total</th></tr></thead>
          <tbody id="models"></tbody>
        </table>
        </details>
      </section>
      <section>
        <details class="fold" open>
        <summary>Upstreams</summary>
        <table>
          <thead><tr><th>Upstream</th><th class="right">Requests</th><th class="right">Tokens</th></tr></thead>
          <tbody id="upstreams"></tbody>
        </table>
        </details>
      </section>
    </div>
    <section>
      <details class="fold">
      <summary>Request Timeline</summary>
      <table>
        <thead><tr><th>Time</th><th>Status</th><th>Model</th><th>Tokens</th><th>Tools</th><th>Path</th><th>Preview</th></tr></thead>
        <tbody id="timelineTable"></tbody>
      </table>
      </details>
    </section>
    <section>
      <details class="fold">
      <summary>Tool History</summary>
      <table>
        <thead><tr><th>Time</th><th>Kind</th><th>Tool</th><th>Call</th><th>Status</th></tr></thead>
        <tbody id="tools"></tbody>
      </table>
      </details>
    </section>
    <section>
      <details class="fold" open>
      <summary>Recent Errors</summary>
      <table>
        <thead><tr><th>Time</th><th>Status</th><th>Mode</th><th>Path</th><th>Request</th></tr></thead>
        <tbody id="errorsTable"></tbody>
      </table>
      </details>
    </section>
    <section>
      <details class="fold">
      <summary>Auxiliary Errors</summary>
      <table>
        <thead><tr><th>Time</th><th>Status</th><th>Mode</th><th>Path</th><th>Request</th></tr></thead>
        <tbody id="auxiliaryErrorsTable"></tbody>
      </table>
      </details>
    </section>
  </main>
  <script>
    const fmt = new Intl.NumberFormat();
    const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    function escapeHtml(value) {
      return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    function text(value) {
      return escapeHtml(value === null || value === undefined || value === '' ? 'unknown' : value);
    }

    function optional(value) {
      return escapeHtml(value === null || value === undefined || value === '' ? '-' : value);
    }

    function row(cells) {
      return '<tr>' + cells.map((cell) => '<td' + (cell.right ? ' class="right"' : '') + '>' + cell.value + '</td>').join('') + '</tr>';
    }

    async function refresh() {
      const [usage, tools, errors, timeline] = await Promise.all([
        fetch('/api/usage/day').then((response) => response.json()),
        fetch('/api/tools/day').then((response) => response.json()),
        fetch('/api/errors/day').then((response) => response.json()),
        fetch('/api/timeline/day').then((response) => response.json())
      ]);

      document.getElementById('totalTokens').textContent = fmt.format(usage.totals.total_tokens);
      document.getElementById('inputTokens').textContent = fmt.format(usage.totals.input_tokens);
      document.getElementById('outputTokens').textContent = fmt.format(usage.totals.output_tokens);
      document.getElementById('requests').textContent = fmt.format(usage.totals.request_count);
      document.getElementById('errors').textContent = fmt.format(usage.totals.error_count);
      document.getElementById('auxiliaryErrors').textContent = fmt.format(usage.totals.auxiliary_error_count);
      document.getElementById('updated').textContent = 'Updated ' + timeFmt.format(new Date(usage.generated_at_ms));

      document.getElementById('models').innerHTML = usage.by_model.map((item) => row([
        { value: text(item.name) },
        { value: fmt.format(item.input_tokens), right: true },
        { value: fmt.format(item.output_tokens), right: true },
        { value: fmt.format(item.total_tokens), right: true }
      ])).join('') || row([{ value: 'No model usage yet' }, { value: '', right: true }, { value: '', right: true }, { value: '', right: true }]);

      document.getElementById('upstreams').innerHTML = usage.by_upstream.map((item) => row([
        { value: text(item.name) },
        { value: fmt.format(item.request_count), right: true },
        { value: fmt.format(item.total_tokens), right: true }
      ])).join('') || row([{ value: 'No upstream usage yet' }, { value: '', right: true }, { value: '', right: true }]);

      document.getElementById('timelineTable').innerHTML = timeline.events.map((item) => {
        const requestPreview = item.request_preview ? '<details><summary>Request' + (item.request_truncated ? ' truncated' : '') + '</summary><pre>' + text(item.request_preview) + '</pre></details>' : '';
        const responsePreview = item.response_preview ? '<details><summary>Response' + (item.response_truncated ? ' truncated' : '') + '</summary><pre>' + text(item.response_preview) + '</pre></details>' : '';
        return row([
          { value: timeFmt.format(new Date(item.started_at_ms)) },
          { value: optional(item.status_code || item.error) },
          { value: optional(item.model) },
          { value: fmt.format(item.total_tokens), right: true },
          { value: fmt.format(item.tool_event_count), right: true },
          { value: text(item.path) },
          { value: requestPreview + responsePreview || '<span class="muted">Capture disabled</span>' }
        ]);
      }).join('') || row([{ value: 'No requests yet' }, { value: '' }, { value: '' }, { value: '', right: true }, { value: '', right: true }, { value: '' }, { value: '' }]);

      document.getElementById('tools').innerHTML = tools.events.map((item) => row([
        { value: timeFmt.format(new Date(item.observed_at_ms)) },
        { value: text(item.event_kind) },
        { value: optional(item.tool_name) },
        { value: '<span class="mono">' + optional(item.call_id) + '</span>' },
        { value: '<span class="status">' + optional(item.status) + '</span>' }
      ])).join('') || row([{ value: 'No tool events yet' }, { value: '' }, { value: '' }, { value: '' }, { value: '' }]);

      document.getElementById('errorsTable').innerHTML = errors.errors.map((item) => row([
        { value: timeFmt.format(new Date(item.started_at_ms)) },
        { value: '<span class="error">' + optional(item.status_code || item.error) + '</span>' },
        { value: text(item.mode) },
        { value: text(item.path) },
        { value: '<span class="mono">' + text(item.request_id) + '</span>' }
      ])).join('') || row([{ value: 'No errors recorded' }, { value: '' }, { value: '' }, { value: '' }, { value: '' }]);

      document.getElementById('auxiliaryErrorsTable').innerHTML = errors.auxiliary_errors.map((item) => row([
        { value: timeFmt.format(new Date(item.started_at_ms)) },
        { value: '<span class="error">' + optional(item.status_code || item.error) + '</span>' },
        { value: text(item.mode) },
        { value: text(item.path) },
        { value: '<span class="mono">' + text(item.request_id) + '</span>' }
      ])).join('') || row([{ value: 'No auxiliary errors recorded' }, { value: '' }, { value: '' }, { value: '' }, { value: '' }]);
    }

    refresh().catch((error) => {
      document.getElementById('updated').innerHTML = '<span class="error">Load failed</span>';
    });
  </script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::telemetry_store::TelemetryStore;

    use super::*;

    #[tokio::test]
    async fn usage_endpoint_returns_empty_dashboard() {
        let store = Arc::new(TelemetryStore::open_in_memory(24).await.unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = dashboard_router(store);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .get(format!("http://{addr}/api/usage/day"))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "status={status}, body={text}");
        let body: crate::telemetry::UsageDashboard = serde_json::from_str(&text).unwrap();
        assert_eq!(body.totals.total_tokens, 0);
        assert_eq!(body.totals.request_count, 0);
        assert_eq!(body.totals.error_count, 0);
        assert_eq!(body.totals.auxiliary_error_count, 0);

        handle.abort();
    }
}
