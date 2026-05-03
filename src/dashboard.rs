use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use tracing::{debug, error, info, warn};

use crate::config::DashboardConfig;
use crate::telemetry::{DEFAULT_QUERY_WINDOW_HOURS, new_ulid};
use crate::telemetry_store::TelemetryStore;

#[derive(Clone)]
pub struct DashboardState {
    store: Arc<TelemetryStore>,
    token: Option<Arc<String>>,
}

pub fn dashboard_router(store: Arc<TelemetryStore>, token: String) -> Router {
    dashboard_router_with_optional_token(store, Some(token))
}

fn dashboard_router_with_optional_token(
    store: Arc<TelemetryStore>,
    token: Option<String>,
) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/usage/day", get(usage_day))
        .route("/api/tools/day", get(tools_day))
        .route("/api/errors/day", get(errors_day))
        .route("/api/timeline/day", get(timeline_day))
        .with_state(DashboardState {
            store,
            token: token.map(Arc::new),
        })
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
    let token = if config.auth_enabled {
        let token_path = expand_home_path(&config.token_path);
        let token = ensure_dashboard_token(&token_path)?;
        info!(
            listen_addr = %listen_addr,
            token_path = %token_path.display(),
            "Dashboard token authentication enabled"
        );
        Some(token)
    } else {
        warn!(
            listen_addr = %listen_addr,
            "Dashboard token authentication disabled"
        );
        None
    };

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(
        listen_addr = %listen_addr,
        "Dashboard server started"
    );
    axum::serve(listener, dashboard_router_with_optional_token(store, token)).await?;
    Ok(())
}

async fn index(State(state): State<DashboardState>, headers: HeaderMap, uri: Uri) -> Response {
    debug!("Serving dashboard HTML");
    if !is_authorized(state.token.as_deref().map(String::as_str), &headers, &uri) {
        return unauthorized_response();
    }
    ([("referrer-policy", "no-referrer")], Html(DASHBOARD_HTML)).into_response()
}

async fn usage_day(State(state): State<DashboardState>, headers: HeaderMap, uri: Uri) -> Response {
    if !is_authorized(state.token.as_deref().map(String::as_str), &headers, &uri) {
        return unauthorized_response();
    }
    let started = Instant::now();
    debug!("Handling dashboard usage endpoint");

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

async fn tools_day(State(state): State<DashboardState>, headers: HeaderMap, uri: Uri) -> Response {
    if !is_authorized(state.token.as_deref().map(String::as_str), &headers, &uri) {
        return unauthorized_response();
    }
    let started = Instant::now();
    debug!("Handling dashboard tools endpoint");

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

async fn errors_day(State(state): State<DashboardState>, headers: HeaderMap, uri: Uri) -> Response {
    if !is_authorized(state.token.as_deref().map(String::as_str), &headers, &uri) {
        return unauthorized_response();
    }
    let started = Instant::now();
    debug!("Handling dashboard errors endpoint");

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

async fn timeline_day(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if !is_authorized(state.token.as_deref().map(String::as_str), &headers, &uri) {
        return unauthorized_response();
    }
    let started = Instant::now();
    debug!("Handling dashboard timeline endpoint");

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

fn expand_home_path(path: &Path) -> std::path::PathBuf {
    let Some(path_text) = path.to_str() else {
        return path.to_path_buf();
    };
    let Some(rest) = path_text.strip_prefix("~/") else {
        return path.to_path_buf();
    };
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(rest)
}

fn ensure_dashboard_token(path: &Path) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match fs::read_to_string(path) {
        Ok(token) => {
            let token = token.trim().to_string();
            if token.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "dashboard token file is empty",
                )
                .into());
            }
            return Ok(token);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let token = format!("{}.{}", new_ulid()?, new_ulid()?);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(format!("{token}\n").as_bytes())?;
    Ok(token)
}

fn is_authorized(token: Option<&str>, headers: &HeaderMap, uri: &Uri) -> bool {
    let Some(token) = token else {
        return true;
    };

    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|candidate| constant_time_eq(candidate, token))
    {
        return true;
    }

    uri.query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .any(|(name, value)| name == "token" && constant_time_eq(&value, token))
        })
        .unwrap_or(false)
}

fn constant_time_eq(candidate: &str, expected: &str) -> bool {
    let candidate = candidate.as_bytes();
    let expected = expected.as_bytes();
    let mut diff = candidate.len() ^ expected.len();
    for index in 0..expected.len() {
        let candidate_byte = candidate.get(index).copied().unwrap_or(0);
        diff |= usize::from(candidate_byte ^ expected[index]);
    }
    diff == 0
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", "Bearer")],
        "dashboard token required",
    )
        .into_response()
}

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Proxy Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@500;600;700;800&family=Geist:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="icon" href="data:,">
  <style>
    :root {
      color-scheme: light;
      --bg: #E8DFCB;
      --paper: #F4ECDC;
      --paper-2: #EFE6D2;
      --paper-3: #F8E9C9;
      --ink: #161412;
      --ink-soft: #3B3530;
      --muted: #7A6F63;
      --rule: rgba(22, 18, 18, 0.10);
      --rule-strong: rgba(22, 18, 18, 0.22);
      --accent: #C2541A;
      --accent-2: #2A6B7A;
      --gold: #B07A2A;
      --warn: #A93518;
      --warn-soft: #F1D9CE;
      --ok: #2A6B7A;
      --ok-soft: #DDE7DD;
      --serif: "Playfair Display", "Cambria", Georgia, serif;
      --sans: "Geist", "Helvetica Neue", Arial, sans-serif;
      --mono: "JetBrains Mono", "Consolas", monospace;
      --shadow: 0 30px 70px -42px rgba(20, 15, 10, 0.45), 0 1px 0 rgba(0, 0, 0, 0.04);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: var(--sans);
      letter-spacing: 0;
      min-height: 100vh;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(90deg, rgba(22, 18, 18, 0.035) 1px, transparent 1px) 0 0 / 42px 42px,
        radial-gradient(circle at 80% 8%, rgba(194, 84, 26, 0.09), transparent 32%),
        radial-gradient(circle at 10% 18%, rgba(42, 107, 122, 0.09), transparent 34%);
      opacity: 0.65;
    }
    header {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 28px;
      padding: 30px 42px 24px;
      max-width: 1480px;
      margin: 0 auto;
      width: 100%;
      border-bottom: 1px solid var(--rule-strong);
      position: relative;
      z-index: 1;
    }
    header::before {
      content: "AI";
      width: 28px;
      height: 28px;
      border: 1px solid rgba(194, 84, 26, 0.45);
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      color: var(--accent);
      font-family: var(--serif);
      font-size: 13px;
      font-weight: 800;
      flex: 0 0 auto;
      position: absolute;
      left: 42px;
      bottom: 28px;
    }
    header > div:first-child {
      padding-left: 44px;
    }
    h1 {
      margin: 0;
      font-family: var(--serif);
      font-size: clamp(42px, 6vw, 84px);
      font-weight: 800;
      line-height: 0.92;
      letter-spacing: 0;
      color: var(--ink);
    }
    .muted {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
    }
    #updated {
      padding: 9px 12px;
      border: 1px solid var(--rule-strong);
      border-radius: 4px;
      background: var(--paper);
      box-shadow: var(--shadow);
      white-space: nowrap;
    }
    main {
      display: grid;
      gap: 18px;
      padding: 26px 42px 42px;
      max-width: 1480px;
      margin: 0 auto;
      width: 100%;
      position: relative;
      z-index: 1;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
    }
    .stat, section {
      background: var(--paper);
      border: 1px solid var(--rule-strong);
      border-radius: 6px;
      box-shadow: var(--shadow);
    }
    .stat {
      padding: 15px 17px;
      min-height: 104px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
    }
    .stat::after {
      content: "";
      position: absolute;
      left: 17px;
      right: 17px;
      bottom: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--accent-2));
      opacity: 0.78;
    }
    .label {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 10.5px;
      font-weight: 600;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }
    .value {
      margin-top: 14px;
      font-family: var(--serif);
      font-size: 36px;
      font-weight: 800;
      line-height: 0.96;
      letter-spacing: 0;
      color: var(--ink);
      font-variant-numeric: tabular-nums;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }
    section { overflow: hidden; }
    .fold {
      max-width: none;
    }
    .fold > summary {
      display: flex;
      align-items: center;
      gap: 8px;
      min-height: 52px;
      padding: 15px 18px;
      border-bottom: 1px solid var(--rule);
      color: var(--ink);
      font-family: var(--serif);
      font-size: 22px;
      font-weight: 700;
      cursor: pointer;
      list-style: none;
      outline: none;
      user-select: none;
    }
    .fold:not([open]) > summary {
      border-bottom: 0;
    }
    .fold > summary:hover {
      background: var(--paper-2);
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
      border-right: 1.5px solid var(--accent);
      border-bottom: 1.5px solid var(--accent);
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
      background: var(--paper-2);
    }
    th, td {
      padding: 11px 18px;
      border-bottom: 1px solid var(--rule);
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 10.5px;
      font-weight: 600;
      height: 40px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    td {
      color: var(--ink-soft);
      line-height: 1.35;
    }
    tbody tr:hover {
      background: rgba(248, 233, 201, 0.42);
    }
    tr:last-child td { border-bottom: 0; }
    .right { text-align: right; }
    .status, .error, .badge {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid var(--rule-strong);
      background: var(--paper-3);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 10.5px;
      font-weight: 600;
      line-height: 1.2;
      letter-spacing: 0.04em;
    }
    .error {
      border-color: rgba(169, 53, 24, 0.28);
      background: var(--warn-soft);
      color: var(--warn);
    }
    .mono { font-family: var(--mono); }
    details { max-width: 520px; }
    summary { cursor: pointer; color: var(--accent); font-weight: 650; }
    td > details {
      margin: 0 0 6px;
    }
    td > details > summary {
      display: inline-flex;
      padding: 4px 8px;
      border: 1px solid var(--rule-strong);
      border-radius: 4px;
      background: var(--paper);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 10.5px;
      letter-spacing: 0.04em;
    }
    td > details > summary:hover {
      background: var(--paper-3);
    }
    pre {
      max-height: 220px;
      overflow: auto;
      margin: 8px 0 0;
      padding: 12px;
      background: rgba(22, 18, 18, 0.05);
      border: 1px solid var(--rule);
      border-radius: 4px;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: var(--mono);
      font-size: 11.5px;
      line-height: 1.35;
    }
    @media (max-width: 900px) {
      header { align-items: start; flex-direction: column; padding: 22px 20px 18px; }
      header::before { display: none; }
      header > div:first-child { padding-left: 0; }
      main { padding: 18px 20px 24px; }
      .stats, .grid { grid-template-columns: 1fr; }
      .value { font-size: 32px; }
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

    const queryToken = new URLSearchParams(window.location.search).get('token');
    if (queryToken) {
      sessionStorage.setItem('dashboardToken', queryToken);
      window.history.replaceState(null, '', window.location.pathname);
    }
    const dashboardToken = sessionStorage.getItem('dashboardToken');
    function apiFetch(path) {
      const options = dashboardToken ? { headers: { Authorization: 'Bearer ' + dashboardToken } } : {};
      return fetch(path, options);
    }

    async function refresh() {
      const [usage, tools, errors, timeline] = await Promise.all([
        apiFetch('/api/usage/day').then((response) => response.json()),
        apiFetch('/api/tools/day').then((response) => response.json()),
        apiFetch('/api/errors/day').then((response) => response.json()),
        apiFetch('/api/timeline/day').then((response) => response.json())
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
        let app = dashboard_router(store, "test-token".to_string());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .get(format!("http://{addr}/api/usage/day?token=test-token"))
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

    #[tokio::test]
    async fn usage_endpoint_rejects_missing_dashboard_token() {
        let store = Arc::new(TelemetryStore::open_in_memory(24).await.unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = dashboard_router(store, "test-token".to_string());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .get(format!("http://{addr}/api/usage/day"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        handle.abort();
    }

    #[tokio::test]
    async fn usage_endpoint_accepts_missing_dashboard_token_when_auth_disabled() {
        let store = Arc::new(TelemetryStore::open_in_memory(24).await.unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = dashboard_router_with_optional_token(store, None);
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

        handle.abort();
    }
}
