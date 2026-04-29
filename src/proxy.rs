use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    response::Response,
};
use bytes::Bytes;
use flate2::read::GzDecoder;
use futures_util::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::convert::Infallible;
use std::io::Read;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use tracing::{debug, error, info, warn};
use url::form_urlencoded;

use crate::config::Config;
use crate::logging::log_redaction;
use crate::middleware::ScanPipeline;
use crate::mitm::{MitmAuthority, normalize_connect_host};
use crate::redactor::Redactor;

/// Shared application state passed to the proxy handler.
pub struct AppState {
    pub config: Config,
    pub pipeline: ScanPipeline,
    pub redactor: Redactor,
    pub http_client: reqwest::Client,
    pub mitm_authority: Option<Arc<MitmAuthority>>,
}

/// Headers that are not safe to forward unchanged through this proxy.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "accept-encoding",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "host",
];
const CONTENT_ENCODING: &str = "content-encoding";
const CONTENT_LENGTH: &str = "content-length";
const SEC_WEBSOCKET_ACCEPT: &str = "sec-websocket-accept";
const SEC_WEBSOCKET_KEY: &str = "sec-websocket-key";
const SEC_WEBSOCKET_PROTOCOL: &str = "sec-websocket-protocol";
const SEC_WEBSOCKET_VERSION: &str = "sec-websocket-version";
const SEC_WEBSOCKET_EXTENSIONS: &str = "sec-websocket-extensions";

type UpstreamWebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Catch-all proxy handler: receives any request, scans & redacts the body,
/// forwards to upstream, and streams the response back.
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    if method == Method::CONNECT {
        return handle_connect(state, req).await;
    }

    let route = upstream_route(&state, &uri, &headers);

    info!(
        method = %method,
        path = %uri.path(),
        upstream = %route.base_url,
        "Incoming request"
    );

    // Build upstream URL
    let upstream_url = route
        .absolute_url
        .unwrap_or_else(|| build_upstream_url(&route.base_url, &uri));
    debug!(mode = "reverse", upstream_path = %uri.path(), "Forwarding to upstream");

    forward_request(
        &state,
        method,
        headers,
        req.into_body(),
        upstream_url,
        route.is_codex_responses || state.config.scanner.enabled,
        route.needs_codex_subscription_payload_normalization,
        "reverse",
    )
    .await
}

async fn handle_connect(state: Arc<AppState>, req: Request<Body>) -> Result<Response, StatusCode> {
    let Some(authority) = req
        .uri()
        .authority()
        .map(|value| value.as_str().to_string())
    else {
        warn!("CONNECT request missing authority");
        return Err(StatusCode::BAD_REQUEST);
    };

    let host = match normalize_connect_host(&authority) {
        Ok(host) => host,
        Err(error) => {
            warn!(target = %authority, error = %error, "CONNECT request has invalid authority");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let use_mitm = state.config.proxy.mitm_enabled
        && state.mitm_authority.is_some()
        && !is_mitm_excluded_host(&state, &host);

    info!(target = %authority, host = %host, mitm = use_mitm, "CONNECT tunnel requested");

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if use_mitm {
                    if let Err(error) =
                        tunnel_mitm_connection(state, upgraded, authority.clone()).await
                    {
                        warn!(target = %authority, error = %error, "CONNECT MITM session failed");
                    }
                } else if let Err(error) = tunnel_upgraded_connection(upgraded, &authority).await {
                    log_connect_tunnel_error(&authority, &error);
                }
            }
            Err(error) => {
                warn!(target = %authority, error = %error, "CONNECT upgrade failed");
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(|error| {
            error!(error = %error, "Failed to build CONNECT response");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn forward_request(
    state: &Arc<AppState>,
    method: Method,
    headers: HeaderMap,
    body: Body,
    upstream_url: String,
    allow_normalization: bool,
    force_codex_store_false: bool,
    mode: &'static str,
) -> Result<Response, StatusCode> {
    let body_bytes = match axum::body::to_bytes(body, state.config.proxy.max_body_size).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(mode, error = %e, "Failed to read request body");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let processed_body = match process_request_body(
        state,
        &headers,
        &body_bytes,
        allow_normalization,
        force_codex_store_false,
    ) {
        Ok(body) => body,
        Err(status) => return Err(status),
    };

    debug!(
        mode,
        original_size = body_bytes.len(),
        forwarded_size = processed_body.bytes.len(),
        "Body processed"
    );

    let (forwarded_headers, final_upstream_url) =
        if state.config.scanner.enabled && state.config.scanner.scan_scope == "full" {
            let scanned_headers = scan_and_redact_headers(state, &headers);
            let redacted_url = scan_and_redact_query_params(state, &upstream_url);
            (scanned_headers, redacted_url)
        } else {
            (headers.clone(), upstream_url)
        };

    let mut upstream_req = state
        .http_client
        .request(reqwest_method(&method), &final_upstream_url);

    upstream_req = forward_headers(
        upstream_req,
        &forwarded_headers,
        processed_body.strip_content_encoding,
    );

    if method != Method::GET && method != Method::HEAD {
        upstream_req = upstream_req.body(processed_body.bytes);
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!(mode, error = %e, "Failed to connect to upstream");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    response_from_upstream(upstream_resp, mode)
}

fn response_from_upstream(
    upstream_resp: reqwest::Response,
    mode: &'static str,
) -> Result<Response, StatusCode> {
    info!(
        mode,
        status = upstream_resp.status().as_u16(),
        "Upstream response received"
    );

    let status = axum::http::StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_ref()),
            HeaderValue::from_bytes(value.as_ref()),
        ) {
            let name_lower = n.as_str().to_ascii_lowercase();
            if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) || name_lower == CONTENT_LENGTH {
                continue;
            }
            response_headers.append(n, v);
        }
    }

    debug!(mode, "Streaming upstream response body");
    let stream = upstream_resp.bytes_stream().map(move |chunk| {
        chunk.map_err(move |e| {
            warn!(mode, error = %e, "Error reading upstream response chunk");
            std::io::Error::other(e)
        })
    });

    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;

    Ok(response)
}

fn is_mitm_excluded_host(state: &AppState, host: &str) -> bool {
    state
        .config
        .proxy
        .mitm_excluded_hosts
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(host))
}

fn log_connect_tunnel_error(target: &str, error: &std::io::Error) {
    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    ) {
        debug!(target = %target, error = %error, "CONNECT tunnel closed");
        return;
    }

    warn!(target = %target, error = %error, "CONNECT tunnel failed");
}

async fn tunnel_upgraded_connection(upgraded: Upgraded, authority: &str) -> std::io::Result<()> {
    let mut server = TcpStream::connect(authority).await?;
    let mut client = TokioIo::new(upgraded);
    copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

async fn tunnel_mitm_connection(
    state: Arc<AppState>,
    upgraded: Upgraded,
    authority: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(mitm_authority) = state.mitm_authority.as_ref() else {
        return Err(Box::new(std::io::Error::other(
            "MITM authority is not configured",
        )));
    };

    let acceptor = mitm_authority.acceptor_for_authority(&authority)?;
    let upgraded = TokioIo::new(upgraded);
    let tls_stream = acceptor.accept(upgraded).await?;
    debug!(target = %authority, "CONNECT MITM TLS handshake completed");

    let service_authority = authority.clone();
    let service_state = state.clone();
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let state = service_state.clone();
        let authority = service_authority.clone();
        async move { Ok::<_, Infallible>(handle_mitm_http_request(state, authority, req).await) }
    });

    http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .with_upgrades()
        .await?;
    debug!(target = %authority, "CONNECT MITM session completed");

    Ok(())
}

async fn handle_mitm_http_request(
    state: Arc<AppState>,
    authority: String,
    req: hyper::Request<Incoming>,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let route = upstream_route(&state, &uri, &headers);
    let upstream_url = route
        .absolute_url
        .unwrap_or_else(|| format!("https://{}{}", authority, path_and_query));

    if is_websocket_upgrade(&headers) {
        return handle_mitm_websocket_upgrade(state, req, upstream_url).await;
    }

    debug!(
        mode = "mitm",
        method = %method,
        path = %path_and_query,
        upstream = %upstream_url,
        "Forwarding decrypted CONNECT request"
    );

    match forward_request(
        &state,
        method,
        headers,
        Body::new(req.into_body()),
        upstream_url,
        route.is_codex_responses || state.config.scanner.enabled,
        route.needs_codex_subscription_payload_normalization,
        "mitm",
    )
    .await
    {
        Ok(response) => response,
        Err(status) => {
            warn!(
                mode = "mitm",
                status = status.as_u16(),
                "MITM request forwarding failed"
            );
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            response
        }
    }
}

async fn handle_mitm_websocket_upgrade(
    state: Arc<AppState>,
    req: hyper::Request<Incoming>,
    upstream_url: String,
) -> Response {
    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let websocket_mode = state.config.proxy.websocket_mode.as_str();

    if websocket_mode == "reject" {
        info!(
            mode = "mitm",
            websocket_mode,
            path = %path,
            "Rejecting WebSocket upgrade to force HTTPS fallback"
        );
        let mut response = Response::new(Body::from("websocket not supported"));
        *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
        return response;
    }

    let Some(sec_key) = headers
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
    else {
        warn!(mode = "mitm", path = %path, "WebSocket upgrade missing Sec-WebSocket-Key");
        let mut response = Response::new(Body::from("missing websocket key"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    };

    let ws_url = websocket_url_from_https(&upstream_url);
    let upstream_request = match build_websocket_upstream_request(&ws_url, &headers) {
        Ok(request) => request,
        Err(error) => {
            warn!(mode = "mitm", error = %error, upstream = %ws_url, "Failed to build upstream WebSocket request");
            let mut response = Response::new(Body::from("bad websocket upstream request"));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            return response;
        }
    };

    let (upstream_ws, upstream_response) = match connect_async(upstream_request).await {
        Ok((websocket, response)) => {
            debug!(
                mode = "mitm",
                status = response.status().as_u16(),
                upstream = %ws_url,
                "Connected upstream WebSocket"
            );
            (websocket, response)
        }
        Err(error) => {
            warn!(mode = "mitm", error = %error, upstream = %ws_url, "Failed to connect upstream WebSocket");
            let mut response = Response::new(Body::from("websocket upstream unavailable"));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            return response;
        }
    };

    let on_upgrade = hyper::upgrade::on(req);
    let state_for_task = state.clone();
    let websocket_mode_owned = websocket_mode.to_string();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(error) = proxy_mitm_websocket(
                    state_for_task,
                    upgraded,
                    upstream_ws,
                    websocket_mode_owned,
                )
                .await
                {
                    warn!(mode = "mitm", error = %error, "WebSocket MITM session failed");
                }
            }
            Err(error) => {
                warn!(mode = "mitm", error = %error, "WebSocket upgrade failed");
            }
        }
    });

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response.headers_mut().insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("Upgrade"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    if let Ok(value) = HeaderValue::from_str(&derive_accept_key(sec_key.as_bytes())) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(SEC_WEBSOCKET_ACCEPT), value);
    }
    if let Some(protocol) = upstream_response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .cloned()
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static(SEC_WEBSOCKET_PROTOCOL), protocol);
    }
    response
}

async fn proxy_mitm_websocket(
    state: Arc<AppState>,
    upgraded: Upgraded,
    mut upstream_ws: UpstreamWebSocket,
    websocket_mode: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(mode = "mitm", websocket_mode = %websocket_mode, "Starting WebSocket MITM session");

    let client_io = TokioIo::new(upgraded);
    let mut client_ws =
        WebSocketStream::from_raw_socket(client_io, Role::Server, Some(WebSocketConfig::default()))
            .await;

    loop {
        tokio::select! {
            client_msg = client_ws.next() => {
                let Some(client_msg) = client_msg else {
                    debug!(mode = "mitm", "Client WebSocket closed");
                    break;
                };
                let message = client_msg?;
                let is_close = matches!(message, Message::Close(_));
                let message = if websocket_mode == "inspect" {
                    redact_websocket_message(&state, message)
                } else {
                    message
                };
                upstream_ws.send(message).await?;
                if is_close {
                    let _ = client_ws.close(None).await;
                    break;
                }
            }
            upstream_msg = upstream_ws.next() => {
                let Some(upstream_msg) = upstream_msg else {
                    debug!(mode = "mitm", "Upstream WebSocket closed");
                    break;
                };
                let message = upstream_msg?;
                let is_close = matches!(message, Message::Close(_));
                client_ws.send(message).await?;
                if is_close {
                    let _ = upstream_ws.close(None).await;
                    break;
                }
            }
        }
    }

    let _ = client_ws.close(None).await;
    let _ = upstream_ws.close(None).await;

    Ok(())
}

fn build_websocket_upstream_request(
    ws_url: &str,
    headers: &HeaderMap,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::client::Request,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mut upstream_request = ws_url.into_client_request()?;
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_ascii_lowercase();
        if is_websocket_hop_header(&name_lower) {
            continue;
        }
        upstream_request
            .headers_mut()
            .append(name.clone(), value.clone());
    }
    Ok(upstream_request)
}

fn redact_websocket_message(state: &AppState, message: Message) -> Message {
    match message {
        Message::Text(text) => {
            let original_len = text.len();
            let redacted = scan_and_redact(state, text.as_str());
            if redacted.len() != original_len || redacted.as_str() != text.as_str() {
                info!(
                    mode = "mitm",
                    original_len,
                    redacted_len = redacted.len(),
                    "Redacted WebSocket text frame"
                );
            }
            Message::Text(redacted.into())
        }
        other => other,
    }
}

fn websocket_url_from_https(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url.to_string()
    }
}

struct UpstreamRoute {
    base_url: String,
    absolute_url: Option<String>,
    is_codex_responses: bool,
    needs_codex_subscription_payload_normalization: bool,
}

/// Pick the upstream by endpoint shape. Anthropic-compatible traffic remains on
/// proxy.anthropic_upstream_url; Codex/OpenAI Responses traffic goes to OpenAI or the
/// ChatGPT subscription backend, matching the harness proxy behavior.
fn upstream_route(state: &AppState, uri: &Uri, headers: &HeaderMap) -> UpstreamRoute {
    if !is_codex_responses_path(uri.path()) {
        return UpstreamRoute {
            base_url: state.config.proxy.anthropic_upstream_url.clone(),
            absolute_url: None,
            is_codex_responses: false,
            needs_codex_subscription_payload_normalization: false,
        };
    }

    if state.config.proxy.codex_subscription_routing_enabled
        && !is_openai_api_key_auth(headers.get("authorization").and_then(|v| v.to_str().ok()))
    {
        return UpstreamRoute {
            base_url: state.config.proxy.codex_subscription_url.clone(),
            absolute_url: Some(subscription_upstream_url(
                state.config.proxy.codex_subscription_url.as_str(),
                uri,
            )),
            is_codex_responses: true,
            needs_codex_subscription_payload_normalization: !is_codex_compact_path(uri.path()),
        };
    }

    UpstreamRoute {
        base_url: state.config.proxy.codex_upstream_url.clone(),
        absolute_url: None,
        is_codex_responses: true,
        needs_codex_subscription_payload_normalization: false,
    }
}

fn is_codex_responses_path(path: &str) -> bool {
    path == "/v1/responses"
        || path.ends_with("/v1/responses")
        || path.contains("/v1/responses/")
        || path.contains("/backend-api/codex/responses")
}

fn is_codex_compact_path(path: &str) -> bool {
    path == "/v1/responses/compact"
        || path.ends_with("/v1/responses/compact")
        || path == "/backend-api/codex/responses/compact"
        || path.ends_with("/backend-api/codex/responses/compact")
}

fn is_openai_api_key_auth(auth: Option<&str>) -> bool {
    auth.is_some_and(|value| value.starts_with("Bearer sk-"))
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has_upgrade_websocket = headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection_has_upgrade = headers
        .get("connection")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });

    has_upgrade_websocket || connection_has_upgrade
}

fn is_websocket_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "upgrade"
            | "host"
            | SEC_WEBSOCKET_ACCEPT
            | SEC_WEBSOCKET_KEY
            | SEC_WEBSOCKET_VERSION
            | SEC_WEBSOCKET_EXTENSIONS
    )
}

fn append_query(base_url: &str, uri: &Uri) -> String {
    let Some(query) = uri.query() else {
        return base_url.to_string();
    };

    if base_url.contains('?') {
        format!("{}&{}", base_url, query)
    } else {
        format!("{}?{}", base_url, query)
    }
}

fn subscription_upstream_url(base_url: &str, uri: &Uri) -> String {
    const CODEX_RESPONSES_PATH: &str = "/backend-api/codex/responses";
    const OPENAI_RESPONSES_PATH: &str = "/v1/responses";

    let request_path = uri.path();
    let suffix = request_path
        .strip_prefix(CODEX_RESPONSES_PATH)
        .or_else(|| request_path.strip_prefix(OPENAI_RESPONSES_PATH))
        .unwrap_or("");
    let base = base_url.trim_end_matches('/');
    let with_suffix = format!("{base}{suffix}");

    append_query(&with_suffix, uri)
}

struct ProcessedBody {
    bytes: Bytes,
    strip_content_encoding: bool,
}

fn process_request_body(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    allow_normalization: bool,
    force_codex_store_false: bool,
) -> Result<ProcessedBody, StatusCode> {
    let normalized = if allow_normalization {
        normalize_body(headers, body, state.config.proxy.max_body_size)?
    } else {
        NormalizedBody {
            bytes: body.clone(),
            decoded: false,
        }
    };

    let normalized = if force_codex_store_false {
        normalize_codex_subscription_payload(normalized)
    } else {
        normalized
    };

    if !state.config.scanner.enabled {
        return Ok(ProcessedBody {
            bytes: normalized.bytes,
            strip_content_encoding: normalized.decoded,
        });
    }

    let has_content_encoding = headers.get(CONTENT_ENCODING).is_some();
    if has_content_encoding && !normalized.decoded {
        warn!("Skipping secret scan because request body content-encoding could not be decoded");
        return Ok(ProcessedBody {
            bytes: normalized.bytes,
            strip_content_encoding: false,
        });
    }

    let Ok(body_string) = std::str::from_utf8(&normalized.bytes) else {
        warn!("Skipping secret scan for non-UTF-8 request body");
        return Ok(ProcessedBody {
            bytes: normalized.bytes,
            strip_content_encoding: normalized.decoded,
        });
    };

    let redacted_body = scan_and_redact(state, body_string);
    Ok(ProcessedBody {
        bytes: Bytes::from(redacted_body.into_bytes()),
        strip_content_encoding: normalized.decoded,
    })
}

fn normalize_codex_subscription_payload(body: NormalizedBody) -> NormalizedBody {
    let Ok(mut json) = serde_json::from_slice::<Value>(&body.bytes) else {
        return body;
    };

    let Some(object) = json.as_object_mut() else {
        return body;
    };

    if object.get("store") == Some(&Value::Bool(false))
        && object.get("stream") == Some(&Value::Bool(true))
    {
        return body;
    }

    object.insert("store".to_string(), Value::Bool(false));
    object.insert("stream".to_string(), Value::Bool(true));
    match serde_json::to_vec(&json) {
        Ok(bytes) => {
            info!("Normalized Codex subscription request payload");
            NormalizedBody {
                bytes: Bytes::from(bytes),
                decoded: body.decoded,
            }
        }
        Err(error) => {
            warn!(error = %error, "Failed to serialize Codex subscription request body");
            body
        }
    }
}

struct NormalizedBody {
    bytes: Bytes,
    decoded: bool,
}

fn normalize_body(
    headers: &HeaderMap,
    body: &Bytes,
    max_body_size: usize,
) -> Result<NormalizedBody, StatusCode> {
    let Some(encoding) = headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
    else {
        return Ok(NormalizedBody {
            bytes: body.clone(),
            decoded: false,
        });
    };

    let decoded = match encoding.as_str() {
        "gzip" => decompress_gzip(body, max_body_size),
        "zstd" => decompress_zstd(body, max_body_size),
        _ => None,
    };

    let normalized = decoded
        .map(|bytes| NormalizedBody {
            bytes,
            decoded: true,
        })
        .unwrap_or_else(|| NormalizedBody {
            bytes: body.clone(),
            decoded: false,
        });

    if normalized.decoded && normalized.bytes.len() > max_body_size {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    Ok(normalized)
}

fn decompress_gzip(body: &[u8], max_body_size: usize) -> Option<Bytes> {
    if body.len() < 2 || body[0] != 0x1f || body[1] != 0x8b {
        return None;
    }

    let decoder = GzDecoder::new(body);
    let mut decompressed = Vec::new();
    decoder
        .take(max_body_size.saturating_add(1) as u64)
        .read_to_end(&mut decompressed)
        .ok()?;
    Some(Bytes::from(decompressed))
}

fn decompress_zstd(body: &[u8], max_body_size: usize) -> Option<Bytes> {
    const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
    if body.len() < ZSTD_MAGIC.len() || &body[..ZSTD_MAGIC.len()] != ZSTD_MAGIC {
        return None;
    }

    let decoder = zstd::stream::read::Decoder::new(body).ok()?;
    let mut decompressed = Vec::new();
    decoder
        .take(max_body_size.saturating_add(1) as u64)
        .read_to_end(&mut decompressed)
        .ok()?;
    Some(Bytes::from(decompressed))
}

/// Scan text for secrets and redact them.
fn scan_and_redact(state: &AppState, text: &str) -> String {
    let matches = state.pipeline.scan(text);

    if matches.is_empty() {
        debug!("No secrets found in request body");
        return text.to_string();
    }

    info!(
        secrets_found = matches.len(),
        "Redacting secrets from request body"
    );

    let mut result = text.to_string();
    // Sort matches by position descending so replacements don't shift offsets
    let mut sorted_matches = matches;
    sorted_matches.sort_by(|a, b| b.start.cmp(&a.start));

    for m in &sorted_matches {
        let redacted = state.redactor.redact(&m.value);
        log_redaction(m, &redacted);
        result = result.replace(&m.value, &redacted);
    }

    result
}

/// Scan and redact non-whitelisted header values when scan_scope is "full".
fn scan_and_redact_headers(state: &AppState, headers: &HeaderMap) -> HeaderMap {
    let whitelist: Vec<String> = state
        .config
        .scanner
        .header_whitelist
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    let mut result = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str())
            || name_lower == CONTENT_ENCODING
            || whitelist.contains(&name_lower)
        {
            result.append(name.clone(), value.clone());
            continue;
        }
        if let Ok(val_str) = value.to_str() {
            let redacted = scan_and_redact(state, val_str);
            if redacted != val_str
                && let Ok(new_val) = HeaderValue::from_str(&redacted)
            {
                result.append(name.clone(), new_val);
                continue;
            }
        }
        result.append(name.clone(), value.clone());
    }
    result
}

/// Scan and redact query parameter values when scan_scope is "full".
fn scan_and_redact_query_params(state: &AppState, url: &str) -> String {
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };

    let mut serializer = form_urlencoded::Serializer::new(String::new());
    let mut changed = false;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        let redacted_value = scan_and_redact(state, &value);
        if redacted_value != value {
            changed = true;
        }
        serializer.append_pair(&key, &redacted_value);
    }

    if changed {
        format!("{}?{}", base, serializer.finish())
    } else {
        url.to_string()
    }
}

/// Build the full upstream URL from base URL and request URI.
fn build_upstream_url(base: &str, uri: &Uri) -> String {
    let base = base.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    format!("{}{}", base, path_and_query)
}

/// Convert axum Method to reqwest Method.
fn reqwest_method(method: &Method) -> reqwest::Method {
    reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET)
}

/// Forward request headers, skipping hop-by-hop headers.
fn forward_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    strip_content_encoding: bool,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        let name_str = name.as_str().to_lowercase();

        // Skip hop-by-hop headers and content-length (reqwest sets it from body)
        if HOP_BY_HOP_HEADERS.contains(&name_str.as_str())
            || name_str == CONTENT_LENGTH
            || (strip_content_encoding && name_str == CONTENT_ENCODING)
        {
            continue;
        }

        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    builder
}
