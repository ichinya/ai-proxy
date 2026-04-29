# AI Proxy — Secret Redaction Reverse Proxy

A Rust reverse proxy that sits between AI coding clients and upstream model APIs, intercepting outgoing requests to detect and redact sensitive data (API keys, tokens, passwords, JWTs, connection strings) before they reach the upstream.

```
Claude Code  -->  ai-proxy (localhost:8080)  -->  api.anthropic.com
Codex CLI    -->  ai-proxy (localhost:8080)  -->  api.openai.com
                  scans & redacts secrets when enabled
```

## Features

- **3-layer secret scanning**: regex patterns, Shannon entropy analysis, structural detection (JWT, connection strings, .env)
- **Partial masking**: `sk-ant-abcdef...xyz` becomes `sk-***...***xyz`
- **SSE streaming**: responses stream through without buffering
- **Configurable scan scope**: body-only or full (body + headers + query params)
- **Anthropic + Codex routing**: Anthropic-compatible requests go to `anthropic_upstream_url`; OpenAI Responses/Codex requests go to `codex_upstream_url` or `codex_subscription_url`
- **HTTP CONNECT + MITM**: clients that use `HTTP_PROXY`/`HTTPS_PROXY` can use blind tunnels or local MITM inspection with WebSocket proxying
- **Compressed payload handling**: gzip/zstd request bodies are decoded with size limits when scanning or Codex forwarding requires it; upstream compressed responses are passed through
- **Rate limiting**: global token-bucket rate limiter (governor)
- **Upstream timeouts**: configurable connect and request timeouts
- **Runtime toggles**: secret scanning, rate limiting, logging, timeouts, body limits, and upstreams can be controlled through environment variables
- **Structured logging**: tracing-based audit log for proxy events and redactions

## Requirements

- Rust 1.85+ (edition 2024)

## Quick Start

```bash
# 1. Clone and build
git clone <repo-url> && cd ai-proxy
cp config.example.toml config.toml
cargo build --release

# 2. Run the proxy
cargo run --release

# 3. Point Claude Code at the proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080

# Or point Codex/OpenAI Responses clients at the proxy
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
```

Or use the Makefile:

```bash
make run        # build and run in release mode
make setup      # copy config.example.toml to config.toml if needed, then build
```

### Quick Start: MITM for Codex Subscription and Claude

This path is for the common setup where Codex uses your ChatGPT/Codex subscription, not an OpenAI API key. Traffic goes through `HTTP_PROXY`/`HTTPS_PROXY`, the proxy performs local MITM inspection, and Codex/Claude are configured globally so you do not need per-shell `export` commands.

Build a Linux binary, upload it, and install it on the server:

```bash
# Build for the server OS/CPU. From macOS, use a Linux builder.
docker run --rm \
  -v "$PWD":/work \
  -w /work \
  rust:1 \
  cargo build --release

SERVER=user@server
scp target/release/ai-proxy config.toml "$SERVER:/tmp/"

ssh "$SERVER" 'sudo install -m 0755 /tmp/ai-proxy /usr/local/bin/ai-proxy'
ssh "$SERVER" 'sudo install -d -m 0755 /etc/ai-proxy'
ssh "$SERVER" 'sudo install -m 0644 /tmp/config.toml /etc/ai-proxy/config.toml'
ssh "$SERVER" 'file /usr/local/bin/ai-proxy'
```

The `file` output on Linux must say `ELF`. If it says `Mach-O`, you uploaded a macOS binary and systemd will fail with `status=203/EXEC` or `Exec format error`. Rebuild inside the Linux Docker container above and upload again.

On the server, set MITM in `/etc/ai-proxy/config.toml`. For remote clients, bind to an address they can reach and restrict access with a firewall or private network:

```toml
[proxy]
listen_addr = "0.0.0.0:8080"
mitm_enabled = true
mitm_ca_cert_path = "certs/ai-proxy-ca.pem"
mitm_ca_key_path = "certs/ai-proxy-ca-key.pem"
websocket_mode = "inspect"
codex_subscription_routing_enabled = true
```

If the server uses `ufw`, allow the proxy port before testing from another machine:

```bash
ssh "$SERVER" 'sudo ufw allow 8080/tcp'
ssh "$SERVER" 'sudo ufw reload'
ssh "$SERVER" 'sudo ufw status verbose'
```

Replace `8080` with the port from `listen_addr`, for example `8764`.

Create the systemd unit on the server:

```bash
ssh "$SERVER" "sudo tee /etc/systemd/system/ai-proxy.service >/dev/null <<'EOF'
[Unit]
Description=AI Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/ai-proxy
ExecStart=/usr/local/bin/ai-proxy
Restart=on-failure
RestartSec=2
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF"
```

The `[Unit]`, `[Service]`, and `[Install]` lines are required. If they are missing, systemd reports `Assignment outside of section`.

Start the service once so it creates the local MITM CA pair. Do not use `/usr/local/bin/ai-proxy --help` as a check: this binary does not implement a CLI help flag, so it starts the server and can fail with `Address already in use` if systemd is already running it.

```bash
ssh "$SERVER" 'sudo systemd-analyze verify /etc/systemd/system/ai-proxy.service'
ssh "$SERVER" 'sudo systemctl daemon-reload'
ssh "$SERVER" 'sudo systemctl enable ai-proxy'
ssh "$SERVER" 'sudo systemctl restart ai-proxy'
ssh "$SERVER" 'sudo systemctl status ai-proxy -l --no-pager'
```

Check that the port is reachable:

```bash
ssh "$SERVER" 'curl -I http://server:8080'
curl -I http://server:8080
```

For a public bind like `listen_addr = "192.145.31.130:8764"`, use that exact host and port:

```bash
ssh "$SERVER" 'curl -I http://192.145.31.130:8764'
curl -I http://192.145.31.130:8764
```

A response such as `404 Not Found` from `api.anthropic.com` is enough to prove the proxy port is reachable; it means the request reached `ai-proxy` and was forwarded upstream. A timeout means the port is still blocked by `ufw`, provider firewall/security group, or another network rule.

Then copy only the CA certificate to each client machine:

```bash
scp "$SERVER:/etc/ai-proxy/certs/ai-proxy-ca.pem" ~/ai-proxy-ca.pem
```

Configure Codex globally with `~/.codex/.env`:

```dotenv
HTTPS_PROXY=http://server:8080
HTTP_PROXY=http://server:8080
SSL_CERT_FILE=/Users/macos/ai-proxy-ca.pem
NO_PROXY=github.com,api.github.com,githubusercontent.com
```

Codex loads `~/.codex/.env` into its process environment. Commands started from
Codex, including `gh`, `git`, and `curl`, inherit these variables and will use the
same proxy unless a host matches `NO_PROXY`. Keep GitHub in `NO_PROXY` unless you
intentionally want GitHub CLI traffic to pass through the local MITM CA.

Run `codex login` once if you are not already signed in, choose ChatGPT sign-in, then run `codex` normally. Do not set `OPENAI_API_KEY` for this subscription flow.

Configure Claude Code globally with `~/.claude/settings.json`:

```json
{
  "env": {
    "HTTPS_PROXY": "http://server:8080",
    "HTTP_PROXY": "http://server:8080",
    "NODE_EXTRA_CA_CERTS": "/Users/macos/ai-proxy-ca.pem"
  }
}
```

Replace `server` and certificate paths with your actual server address and local CA path. For local testing on the same machine, use `http://127.0.0.1:8080` instead.

## Configuration

All settings are in `config.toml`. Start from `config.example.toml` for a fresh deployment:

```bash
cp config.example.toml config.toml
```

### Proxy

```toml
[proxy]
listen_addr = "127.0.0.1:8080"       # proxy listen address
anthropic_upstream_url = "https://api.anthropic.com"
codex_upstream_url = "https://api.openai.com"
codex_subscription_url = "https://chatgpt.com/backend-api/codex/responses"
codex_subscription_routing_enabled = true  # route Codex subscription auth tokens to ChatGPT backend
rate_limit_enabled = true
max_body_size = 10485760              # max request body size (bytes), default 10 MB
connect_timeout_secs = 10             # upstream connect timeout
request_timeout_secs = 0              # total request timeout; 0 disables it for streaming/SSE
rate_limit_rps = 50                   # max requests per second
mitm_enabled = false                  # opt-in HTTPS CONNECT inspection
mitm_ca_cert_path = "certs/ai-proxy-ca.pem"
mitm_ca_key_path = "certs/ai-proxy-ca-key.pem"
mitm_cert_cache_size = 256
mitm_excluded_hosts = []              # hostnames that should keep blind CONNECT tunneling
websocket_mode = "inspect"            # reject | passthrough | inspect; default inspect
```

### Redaction

```toml
[redaction]
strategy = "partial"    # masking strategy
prefix_len = 3          # visible prefix characters
suffix_len = 3          # visible suffix characters
mask = "***...***"      # mask placeholder
```

A secret like `sk-ant-abcdef123456789xyz` becomes `sk-***...***xyz`. Secrets shorter than `prefix_len + suffix_len + 2` characters are fully masked.

### Scanner

```toml
[scanner]
enabled = true          # false disables all secret scanning and redaction
scan_scope = "body"     # "body" = request body only, "full" = body + headers + query params
header_whitelist = [    # headers skipped during scanning (auth headers forwarded as-is)
    "x-api-key",
    "authorization",
    "cookie",
    "anthropic-version",
    "anthropic-beta",
]
```

### Environment Overrides

Runtime settings can be overridden without editing `config.toml`:

```bash
AI_PROXY_SECRET_SCANNING_ENABLED=false  # disable all scanners and redaction
AI_PROXY_REGEX_SCANNER_ENABLED=false
AI_PROXY_ENTROPY_SCANNER_ENABLED=false
AI_PROXY_STRUCTURAL_SCANNER_ENABLED=false
AI_PROXY_SCAN_SCOPE=full
AI_PROXY_REDACTION_STRATEGY=partial
AI_PROXY_REDACTION_PREFIX_LEN=3
AI_PROXY_REDACTION_SUFFIX_LEN=3
AI_PROXY_REDACTION_MASK='***...***'
AI_PROXY_RATE_LIMIT_ENABLED=false       # disable rate limiting
AI_PROXY_LOGGING_ENABLED=false          # disable tracing subscriber setup
AI_PROXY_MAX_BODY_SIZE=20971520         # request body limit in bytes
AI_PROXY_RATE_LIMIT_RPS=100
AI_PROXY_CONNECT_TIMEOUT_SECS=10
AI_PROXY_REQUEST_TIMEOUT_SECS=0       # 0 disables total request timeout
AI_PROXY_LISTEN_ADDR=127.0.0.1:8080
AI_PROXY_ANTHROPIC_UPSTREAM_URL=https://api.anthropic.com
AI_PROXY_CODEX_UPSTREAM_URL=https://api.openai.com
AI_PROXY_CODEX_SUBSCRIPTION_URL=https://chatgpt.com/backend-api/codex/responses
AI_PROXY_CODEX_SUBSCRIPTION_ROUTING_ENABLED=false
AI_PROXY_MITM_ENABLED=false
AI_PROXY_MITM_CA_CERT_PATH=certs/ai-proxy-ca.pem
AI_PROXY_MITM_CA_KEY_PATH=certs/ai-proxy-ca-key.pem
AI_PROXY_MITM_CERT_CACHE_SIZE=256
AI_PROXY_MITM_EXCLUDED_HOSTS=example.com,internal.example
AI_PROXY_WEBSOCKET_MODE=inspect
```

Boolean env vars accept `true/false`, `1/0`, `on/off`, or `yes/no`.

#### Layer 1: Regex Patterns

```toml
[scanner.regex]
enabled = true

[[scanner.regex.patterns]]
name = "aws_access_key"
pattern = "AKIA[0-9A-Z]{16}"
```

Built-in patterns: AWS keys, GitHub tokens, Anthropic/OpenAI API keys, generic secret assignments, private key blocks. Add custom patterns by appending `[[scanner.regex.patterns]]` entries.

#### Layer 2: Entropy Analysis

```toml
[scanner.entropy]
enabled = true
threshold = 4.5          # Shannon entropy threshold (0-8)
min_length = 20          # minimum token length to analyze
max_length = 256         # maximum token length
keywords = ["key", "secret", "token", "password", "passwd", "credential", "auth"]
keyword_proximity = 50   # max distance (bytes) from keyword to flag a token
```

High-entropy strings are only flagged when a secret-related keyword appears nearby.

#### Layer 3: Structural Detection

```toml
[scanner.structural]
enabled = true
detect_jwt = true                # eyJ... JWT tokens
detect_connection_strings = true # mongodb://, postgres://, etc.
detect_env_patterns = true       # SECRET_KEY=value, export API_KEY=value
```

## Usage with Claude Code

Set the base URL environment variable so Claude Code sends requests through the proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
```

The proxy forwards all auth headers (`x-api-key`, `authorization`, etc.) as-is to the upstream. Only the request body (and optionally headers/query params) is scanned for accidentally leaked secrets.

### Global Claude Code Settings

Claude Code can apply environment variables to every session from `~/.claude/settings.json`. Use this instead of exporting variables in every shell:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8080"
  }
}
```

For HTTPS proxy/MITM mode, configure the proxy variables and trust the local CA with `NODE_EXTRA_CA_CERTS`:

```json
{
  "env": {
    "HTTPS_PROXY": "http://127.0.0.1:8080",
    "HTTP_PROXY": "http://127.0.0.1:8080",
    "NODE_EXTRA_CA_CERTS": "/Users/macos/Projects/2080/ai-proxy/certs/ai-proxy-ca.pem"
  }
}
```

## Usage with Codex

Set `OPENAI_BASE_URL` so Codex/OpenAI Responses traffic goes through the proxy:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
```

Requests matching `/v1/responses` are forwarded by auth type. `Bearer sk-...` API keys go to `codex_upstream_url`. Other bearer tokens are treated as Codex subscription tokens and, by default, are routed to `codex_subscription_url`. Set `codex_subscription_routing_enabled = false` only if you intentionally use opaque bearer tokens with an OpenAI-compatible provider.

For Codex subscription traffic, `chatgpt.com/backend-api/codex/responses` is stricter than the public Responses API. The proxy normalizes JSON request bodies on the base `/responses` route to `store: false` and `stream: true`. It also preserves suffixes such as `/compact`, so remote compaction requests continue to hit `/backend-api/codex/responses/compact`; compact payloads are forwarded without adding `store` or `stream`.

Some Codex modes ignore `OPENAI_BASE_URL` and use `HTTPS_PROXY` with `CONNECT` to `chatgpt.com` instead:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=github.com,api.github.com,githubusercontent.com
codex
```

This works as a blind CONNECT tunnel. Because the tunneled traffic remains encrypted end-to-end, secret scanning/redaction is not applied inside that HTTPS tunnel. Use the base-url mode when you need this proxy to inspect and redact request bodies.

### HTTPS CONNECT Inspection (MITM)

Set `mitm_enabled = true` to inspect HTTPS traffic that arrives through `HTTP_PROXY`/`HTTPS_PROXY`. On startup, the proxy loads `mitm_ca_cert_path` and `mitm_ca_key_path`. If both files are absent, it creates a new local CA certificate and private key automatically. If only one file exists, startup fails so an accidental certificate/key mismatch does not silently break TLS.

```toml
[proxy]
mitm_enabled = true
mitm_ca_cert_path = "certs/ai-proxy-ca.pem"
mitm_ca_key_path = "certs/ai-proxy-ca-key.pem"
mitm_excluded_hosts = ["example.com"]
websocket_mode = "inspect"
```

After the first start, install or trust the CA certificate from `mitm_ca_cert_path` on the client machine. Do not install the private key. The proxy itself does not need to run as root for local use on `127.0.0.1:8080`; administrator privileges are only needed for actions like installing the CA into a system trust store, installing a systemd service, writing under `/usr/local/bin` or `/etc`, or binding privileged ports below 1024.

For local Codex testing, the practical setup is:

```bash
cd /Users/macos/Projects/2080/ai-proxy
RUST_LOG=info cargo run
```

Then start Codex from another terminal with the proxy and CA bundle:

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=/Users/macos/Projects/2080/ai-proxy/certs/ai-proxy-ca.pem
export NO_PROXY=github.com,api.github.com,githubusercontent.com
codex
```

`SSL_CERT_FILE` is required for Codex CLI builds that do not use the macOS system keychain. If the CA file is regenerated, restart the proxy and update `SSL_CERT_FILE` to the current `mitm_ca_cert_path`.

### Global Codex Environment

Codex uses `$CODEX_HOME` for global state and config; by default that is `~/.codex`. For environment variables, use `~/.codex/.env` (with a leading dot), not `~/.codex/env`.

Create or edit `~/.codex/.env`:

```dotenv
HTTPS_PROXY=http://127.0.0.1:8080
HTTP_PROXY=http://127.0.0.1:8080
SSL_CERT_FILE=/Users/macos/Projects/2080/ai-proxy/certs/ai-proxy-ca.pem
NO_PROXY=github.com,api.github.com,githubusercontent.com
```

After that, `codex` can be started without per-shell exports. Codex filters `CODEX_` variables from this dotenv file, so set `CODEX_HOME` in the OS shell or service manager if you need a non-default Codex home. The dotenv values become normal process environment variables, so subprocesses launched by Codex inherit them. `NO_PROXY` keeps GitHub tooling from being sent through the MITM proxy and avoids certificate trust failures in tools that do not use `SSL_CERT_FILE`.

### GitHub CLI and Proxy Inheritance

Codex tool commands run as subprocesses of the Codex CLI. If `~/.codex/.env`
sets `HTTP_PROXY` or `HTTPS_PROXY`, tools such as `gh`, `git`, `curl`, package
managers, and test runners inherit those variables. That is useful for AI client
traffic, but it can accidentally route unrelated HTTPS traffic through the MITM
proxy.

Keep GitHub in `NO_PROXY` unless you explicitly want to inspect GitHub traffic:

```dotenv
NO_PROXY=github.com,api.github.com,githubusercontent.com
```

To confirm what a command will use, run:

```bash
env | grep -i proxy
gh api /meta
```

If `gh` fails with a certificate error like `x509: "api.github.com" certificate
is not trusted`, it is usually being sent through the MITM proxy. Add or fix
`NO_PROXY`, then restart Codex so the new dotenv values are loaded. If you do
want `gh` to go through MITM, install the `ai-proxy` CA certificate into the
trust store used by GitHub CLI; `SSL_CERT_FILE` alone may not be enough on
macOS builds that use the system keychain.

For API-key mode, Codex also has `~/.codex/config.toml`; current Codex builds support an OpenAI base URL override there:

```toml
openai_base_url = "http://127.0.0.1:8080/v1"
```

For ChatGPT subscription mode, prefer the `~/.codex/.env` proxy setup above so Codex's `chatgpt.com` traffic goes through MITM inspection.

When MITM is enabled and a host is not listed in `mitm_excluded_hosts`, CONNECT traffic is decrypted locally, request bodies are scanned/redacted, and the request is forwarded upstream over HTTPS. Hosts in `mitm_excluded_hosts` continue to use blind CONNECT tunneling.

`websocket_mode` controls WebSocket upgrades inside MITM sessions:

- `inspect` (default) proxies WebSocket traffic and scans/redacts client text frames before forwarding them upstream.
- `passthrough` proxies WebSocket traffic without scanning frames.
- `reject` returns `501 Not Implemented` for WebSocket upgrades and forces clients such as Codex to fall back to HTTPS transport.

## Logging

Logging uses `tracing` with the `RUST_LOG` environment variable:

```bash
RUST_LOG=info cargo run    # default: info level
RUST_LOG=debug cargo run   # verbose: see scan pipeline details
RUST_LOG=trace cargo run   # very verbose: see individual matches
```

Each redaction is logged as a structured event:

```
INFO Secret redacted scanner=regex pattern=aws_access_key original_len=20 redacted_to="AKI***...***PLE"
```

Set `AI_PROXY_LOGGING_ENABLED=false` to skip tracing subscriber initialization.

## Deployment

The production server does not need Rust, Cargo, or the source tree. It only needs a Linux `ai-proxy` binary and `config.toml`.

### Build a Linux Binary

Build on Linux, in CI, or inside a Linux container. If your local machine is macOS or Windows, do not copy the local `target/release/ai-proxy` binary directly to the server; build for Linux first.

Example using Docker from macOS/Windows/Linux:

```bash
docker run --rm \
  -v "$PWD":/work \
  -w /work \
  rust:1 \
  cargo build --release
```

This produces a Linux binary at `target/release/ai-proxy`.

### Upload a Local Binary over SSH

If you built the binary for the server's OS and CPU architecture, upload it directly with `scp` and install it over SSH:

```bash
scp target/release/ai-proxy user@server:/tmp/ai-proxy
scp config.toml user@server:/tmp/config.toml

ssh user@server 'sudo install -m 0755 /tmp/ai-proxy /usr/local/bin/ai-proxy'
ssh user@server 'sudo install -d -m 0755 /etc/ai-proxy'
ssh user@server 'sudo install -m 0644 /tmp/config.toml /etc/ai-proxy/config.toml'
```

### Install on the Server

Copy the Linux binary and config to the server, then install them:

```bash
sudo install -m 0755 target/release/ai-proxy /usr/local/bin/ai-proxy
sudo install -d -m 0755 /etc/ai-proxy
sudo install -m 0644 config.toml /etc/ai-proxy/config.toml
```

After this, edit the runtime config here:

```bash
sudo nano /etc/ai-proxy/config.toml
```

For MITM mode on a server, the important part of `/etc/ai-proxy/config.toml` is:

```toml
[proxy]
listen_addr = "127.0.0.1:8080"
mitm_enabled = true
mitm_ca_cert_path = "certs/ai-proxy-ca.pem"
mitm_ca_key_path = "certs/ai-proxy-ca-key.pem"
websocket_mode = "inspect"
codex_subscription_routing_enabled = true
```

Use `listen_addr = "0.0.0.0:8080"` only if remote clients need to connect to this server. In that case, restrict access with a firewall, VPN, or private network; the proxy forwards authentication headers to upstream providers.

If the server uses `ufw`, allow the proxy port:

```bash
sudo ufw allow 8080/tcp
sudo ufw reload
sudo ufw status verbose
```

Replace `8080` with the port from `listen_addr`, for example `8764`.

Create the systemd service file separately at `/etc/systemd/system/ai-proxy.service`:

```bash
sudo nano /etc/systemd/system/ai-proxy.service
```

Put this service definition in `/etc/systemd/system/ai-proxy.service`. The section headers `[Unit]`, `[Service]`, and `[Install]` must be present exactly as shown; otherwise systemd reports `Assignment outside of section` and refuses the unit.

```ini
[Unit]
Description=AI Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/ai-proxy
ExecStart=/usr/local/bin/ai-proxy
Restart=on-failure
RestartSec=2
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Verify the unit before starting it, then reload systemd and start the service:

```bash
sudo systemd-analyze verify /etc/systemd/system/ai-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now ai-proxy
sudo systemctl status ai-proxy -l --no-pager
```

If `systemd-analyze verify` prints `Assignment outside of section`, the service file was pasted without the `[Unit]`, `[Service]`, or `[Install]` header lines. If `systemctl status` shows `status=203/EXEC`, check the binary with `file /usr/local/bin/ai-proxy`; `Mach-O` means a macOS binary was uploaded, while Linux needs an `ELF` binary.

Check that the port is reachable after the service starts:

```bash
curl -I http://server:8080
```

For a public bind like `listen_addr = "192.145.31.130:8764"`, use that exact host and port:

```bash
curl -I http://192.145.31.130:8764
```

A response such as `404 Not Found` from `api.anthropic.com` is enough to prove the proxy port is reachable; it means the request reached `ai-proxy` and was forwarded upstream. A timeout means the port is still blocked by `ufw`, provider firewall/security group, or another network rule.

Optional hardening can be added after the basic service starts successfully:

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/ai-proxy
```

For MITM mode, the proxy can create the CA files on first start if the configured paths do not exist. With `WorkingDirectory=/etc/ai-proxy`, the relative CA paths above resolve to `/etc/ai-proxy/certs/ai-proxy-ca.pem` and `/etc/ai-proxy/certs/ai-proxy-ca-key.pem`. Trust only `/etc/ai-proxy/certs/ai-proxy-ca.pem` on client machines; do not copy or trust the private key.

The server handles Ctrl+C and SIGTERM with graceful shutdown.

## Testing

```bash
make test       # run all tests
make check      # type-check without building
```

Unit tests cover all scanners and the redactor. Integration tests spin up mock upstream servers and verify end-to-end redaction, Codex routing, compressed request/response handling, SSE streaming, duplicate headers, and body size limits.

## Project Structure

```
src/
  main.rs                        # entrypoint: config, pipeline, router, server
  lib.rs                         # library root
  config.rs                      # configuration structs and loader
  mitm.rs                        # local CA loading/generation and CONNECT TLS interception
  redactor.rs                    # secret masking (partial mask strategy)
  proxy.rs                       # reverse proxy handler, scan & redact logic
  logging.rs                     # structured logging setup
  middleware/
    mod.rs                       # SecretScanner trait, ScanPipeline
    regex_scanner.rs             # Layer 1: regex pattern matching
    entropy_scanner.rs           # Layer 2: Shannon entropy + keyword proximity
    structural_scanner.rs        # Layer 3: JWT, connection strings, .env
tests/
  integration_test.rs            # end-to-end proxy tests
config.toml                      # runtime configuration
```

## License

MIT
