# OIDC Auth Server

An OIDC server written in Go with production-oriented hexagonal architecture, supporting Authorization Code Flow, refresh token rotation, brute-force lockout, and a full OIDC provider surface.

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.26+ | Build and run |
| `ssh-keygen` | any | Generate RSA key pair |
| `openssl` | any | Convert public key format |
| `curl` + `jq` | any | E2E test script |
| `k6` | any | Smoke tests (optional) |
| `act` | any | Run CI jobs locally (optional) |

---

## Features

- **Authorization Code Flow** — state and nonce validation, PKCE (S256)
- **Token lifecycle** — RS256-signed access tokens, opaque refresh tokens with rotation, ID tokens with nonce
- **Security** — CSRF protection on sign-in, brute-force lockout after 3 failed attempts, atomic session consumption, rate limiting
- **OIDC provider surface** — Discovery, JWKS, UserInfo, token introspection (RFC 7662), token revocation (RFC 7009), logout
- **Storage** — pluggable: file-based (default) or MongoDB
- **Cache** — pluggable: in-memory (default) or Redis
- **Password reset** — email-based reset flow; logs reset links to stdout when `SMTP_HOST` is unset

---

## Repository Map

```
cmd/
  auth/           — server entry point, wiring, config
  backend/        — local browser-based OIDC test harness (localhost:3000)
modules/
  auth/
    application/  — use cases (command/, query/, service/)
    domain/       — entities and value objects
    port/         — outbound port interfaces
    adapter/      — inbound HTTP router (router.go)
    adapter/out/  — outbound adapters (JWT, repos, email)
    errors/       — domain error codes
handler/
  web/            — HTTP handlers, middleware, binding, response
core/
  cache/          — cache port interface
  error/          — shared error types and codes
  jwt/            — JWT claims types
  uow/            — unit-of-work interface
  usecase/        — dispatcher and registry
  validator/      — struct validation helpers
  web/            — server config and cookie helpers
infrastructure/
  jwt/            — RS256 JWT service
  cache/          — Redis and in-memory cache
  repository/     — MongoDB and file-based repo drivers
  smtp/           — persistent SMTP client (STARTTLS, reconnect, deadline enforcement)
e2e/              — shell-based end-to-end test suite
smoke_test/       — k6 load/smoke scripts per endpoint
http/             — auth.http IDE request file (VS Code / IntelliJ)
docs/             — architecture diagrams, flow analysis, API spec
```

---

## Architecture

This project follows hexagonal architecture (ports & adapters). The application core is fully isolated from HTTP and infrastructure concerns.

```
         ┌─────────────────────────────────────────┐
         │           Application Core               │
         │                                          │
  HTTP   │  application/command   domain/entity     │  File / Mongo
  Gin  ──┤  application/query     modules/auth/port ├── infrastructure/
  JSON   │  application/define    modules/auth/     │  repository/
         │                        errors            │  cache/
         └─────────────────────────────────────────┘
              ▲ driving ports            driven ports ▼
         handler/web/              modules/auth/adapter/out/
```

Sequence diagram: [`docs/oidc-flow-current.mermaid`](docs/oidc-flow-current.mermaid)  
OpenAPI spec: [`docs/auth.yaml`](docs/auth.yaml)

---

## Quick Start

### 1. Generate RSA key pair

```sh
mkdir -p cmd/auth/.secret

ssh-keygen -t rsa -b 2048 -m PEM -N "" -f cmd/auth/.secret/private_key.pem

openssl rsa -in cmd/auth/.secret/private_key.pem -pubout \
  -outform PEM -out cmd/auth/.secret/public_key.pem
```

### 2. Create `cmd/auth/.env`

The server loads config from `cmd/auth/.env` by default (relative to `cmd/auth/main.go`). Use `ENV_PATH` to point elsewhere.

```sh
cat > cmd/auth/.env << EOF
PORT=:9876
PRIVATE_KEY_PATH=cmd/auth/.secret/private_key.pem
PUBLIC_KEY_PATH=cmd/auth/.secret/public_key.pem
JWT_KID=local
JWT_ISSUER=http://localhost:9876
REPOSITORY_USED=file
FILE_DIR=tmp
USER_FILE_PATH=user.json
OAUTH_CLIENT_REDIRECT_WHITELIST=my_client http://localhost:3000/callback;smoke-client https://app.example.com/callback
OAUTH_POST_LOGOUT_REDIRECT_ALLOWLIST=http://localhost:3000
COOKIE_SECURE=false
EOF
```

A fully annotated example is at [`cmd/auth/.env.example`](cmd/auth/.env.example).

### 3. Run the auth server

```sh
go run cmd/auth/main.go
```

Server starts at **http://localhost:9876**  
OIDC Discovery: http://localhost:9876/.well-known/openid-configuration

### 4. Run the test client (optional)

`cmd/backend` is a browser-based OIDC client for exercising the full Authorization Code Flow manually.

```sh
go run cmd/backend/main.go
```

Client starts at **http://localhost:3000** — click "Login with IdP" to initiate the flow.

---

## Development Workflow

```sh
# Format
gofmt -w .

# Vet
go vet ./...

# Lint (matches CI)
golangci-lint run

# Unit tests (all packages)
go test ./...

# Unit tests — single package, no cache
go test -count=1 ./modules/auth/application/command/...

# Race detector
go test -race ./...

# Build
go build ./...
```

---

## Tests

### Unit tests

Table-driven tests alongside the code they test. Run before any commit touching use cases, commands, queries, entities, or repositories.

```sh
go test ./...
```

### E2E tests (`e2e/test_auth.sh`)

Shell script that exercises the full server over HTTP: sign-up, password grant, Authorization Code Flow (CSRF, state, nonce), refresh, introspect, revoke, logout.

```sh
# Server already running (CI / remote / Docker)
BASE_URL=http://localhost:9876 bash e2e/test_auth.sh

# Let the script start and stop the server for you (local convenience)
START_SERVER=1 bash e2e/test_auth.sh
```

`START_SERVER=1` runs `go run ./cmd/auth/main.go` in the background using `cmd/auth/.env`, waits up to 30 seconds for readiness, then kills the process on exit.

### Smoke tests (`smoke_test/`)

k6 scripts covering each endpoint area, plus `all.js` as a combined suite. Use for load testing or verifying a deployed environment.

The smoke tests use `client_id=smoke-client` and `redirect_uri=https://app.example.com/callback`, so the env must include that entry in `OAUTH_CLIENT_REDIRECT_WHITELIST` — the Quick Start `.env` above already includes it.

```sh
k6 run smoke_test/all.js
k6 run -e BASE_URL=http://staging:9876 smoke_test/all.js
```

### IDE request file (`http/auth.http`)

VS Code REST Client / IntelliJ HTTP Client file with pre-built requests for every endpoint. Useful for manual exploration.

### CI

```sh
act -j e2e       # full e2e
act -j test      # build + vet + unit tests (race)
act -j lint      # golangci-lint
act -j vuln      # govulncheck
act -j licenses  # license compliance
act -j secrets   # gitleaks secret scan
```

---

## API Reference

Full OpenAPI spec: [`docs/auth.yaml`](docs/auth.yaml)

### OIDC / OAuth2

| Method | Path | Description |
|---|---|---|
| `GET` | `/authorize` | Start Authorization Code Flow |
| `GET` | `/sign-in` | Sign-in page (CSRF token injected) |
| `POST` | `/sign-in` | Submit credentials; issues auth code |
| `POST` | `/token` | Token endpoint — `authorization_code`, `refresh_token`, `password` grants |
| `GET` | `/userinfo` | UserInfo claims (Bearer token) |
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery document |
| `GET` | `/.well-known/jwks.json` | JSON Web Key Set |

### Session management

| Method | Path | Description |
|---|---|---|
| `GET` | `/oidc/logout` | Session termination |
| `POST` | `/oidc/revoke` | Token revocation (RFC 7009) |
| `POST` | `/oidc/introspect` | Token introspection (RFC 7662) |
| `GET` | `/oidc/me` | Profile (authenticated) |

### Keycloak-compatible aliases

| Method | Path | Canonical equivalent |
|---|---|---|
| `GET` | `/protocol/openid-connect/auth` | `/authorize` |
| `POST` | `/protocol/openid-connect/token` | `/token` |
| `GET` | `/protocol/openid-connect/certs` | `/.well-known/jwks.json` |
| `GET` | `/protocol/openid-connect/userinfo` | `/userinfo` |

### Account

| Method | Path | Description |
|---|---|---|
| `GET` | `/sign-up` | Sign-up page |
| `POST` | `/sign-up` | Register a new user |
| `POST` | `/forgot-password` | Send password reset email |
| `POST` | `/reset-password` | Apply reset token and new password |
| `POST` | `/api/v3/update-profile` | Update username / nickname / email (Bearer token) |

### Observability

| Method | Path | Description |
|---|---|---|
| `GET` | `/debug/vars` | Expvar metrics (failed logins, tokens issued) |

---

## Persistence

File storage writes two files under `FILE_DIR` (default `tmp/`):

| File | Contents |
|---|---|
| `user.json` | User accounts |
| `refresh_tokens.json` | Active refresh tokens |

Both are safe to delete to reset local state. They are created automatically on first write.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Server panics at startup | `cmd/auth/.env` not found — check the path or set `ENV_PATH` |
| `failed to parse private key` | Key was generated with a passphrase — regenerate with `-N ""` |
| `client redirect_uri not valid` | `redirect_uri` in the request is not in `OAUTH_CLIENT_REDIRECT_WHITELIST` |
| `auth_session` cookie not sent to `/sign-in` | Cookie was blocked by `SameSite=Strict`; server correctly uses `SameSite=Lax` — check client |
| Redis connection errors | Server falls back to in-memory cache automatically; check logs for the warning |
| Port already in use | Another process on `:9876` — change `PORT` in `.env` |
| E2E script fails: `jq: command not found` | Install `jq` |
| Stale user / token state | Delete `tmp/user.json` and `tmp/refresh_tokens.json`, then restart |
| E2E logout test returns 200 instead of 302 | `OAUTH_POST_LOGOUT_REDIRECT_ALLOWLIST` not set — add `http://localhost:3000` to the allowlist |

---

## Configuration

All configuration is read from `cmd/auth/.env` by default, or the path set in `ENV_PATH`.

### Required

| Variable | Example | Description |
|---|---|---|
| `PORT` | `:9876` | Listen address |
| `PRIVATE_KEY_PATH` | `cmd/auth/.secret/private_key.pem` | RSA private key for JWT signing (unencrypted PEM) |
| `PUBLIC_KEY_PATH` | `cmd/auth/.secret/public_key.pem` | RSA public key for JWT verification |
| `JWT_KID` | `local` | Key ID embedded in JWT header |
| `JWT_ISSUER` | `http://localhost:9876` | `iss` claim value — must match the URL clients use |
| `REPOSITORY_USED` | `file` \| `mongo` | Storage backend |

### Storage — file (default)

| Variable | Example | Description |
|---|---|---|
| `FILE_DIR` | `tmp` | Directory for file-based repositories |
| `USER_FILE_PATH` | `user.json` | User store filename within `FILE_DIR` |

### Storage — MongoDB

| Variable | Description |
|---|---|
| `MONGO_HOST` | MongoDB host |
| `MONGO_USER` | Username |
| `MONGO_PASSWORD` | Password |
| `MONGO_AUTH_SOURCE` | Auth database |
| `MONGO_DATABASE` | Target database |

### Cache — Redis (optional, falls back to in-memory)

If `REDIS_ADDR` is unset, the server uses an in-memory cache. In-memory cache is not shared across instances.

| Variable | Description |
|---|---|
| `REDIS_ADDR` | `host:port` — set to enable Redis |
| `REDIS_PASSWORD` | Redis password (optional) |
| `REDIS_DB` | Redis DB index (default `0`) |

### OAuth / OIDC

| Variable | Example | Description |
|---|---|---|
| `OAUTH_CLIENT_REDIRECT_WHITELIST` | `client_a https://a.example.com/cb;client_b https://b.example.com/cb,https://b.example.com/cb2` | Semicolon-separated entries of `client_id uri[,uri…]`; defaults to `client-123` with localhost callbacks if unset |
| `OAUTH_POST_LOGOUT_REDIRECT_ALLOWLIST` | `https://app.example.com` | Comma-separated allowed post-logout URIs |
| `OAUTH_SCOPE_ALLOWLIST` | `openid,email,profile` | Comma-separated allowed scopes (default: `openid email profile phone`) |
| `CORS_ORIGINS` | `https://app.example.com` | Comma-separated CORS origins (default: `*`) |
| `COOKIE_SECURE` | `true` | Set `Secure` flag on cookies — enable in production (requires HTTPS) |

### SMTP (optional — required to send real password reset emails; logs to stdout otherwise)

| Variable | Description |
|---|---|
| `SMTP_HOST` | SMTP server host |
| `SMTP_PORT` | SMTP server port |
| `SMTP_FROM` | Sender address |
| `APP_BASE_URL` | Base URL used in reset email links |

### Other

| Variable | Description |
|---|---|
| `ENV_PATH` | Override default `cmd/auth/.env` location |

---

## Timeouts & TTL Reference

### OIDC / Auth

| Value | Duration | Constant | Source |
|---|---|---|---|
| Auth code TTL | 5 minutes | `AuthCodeTTL` | `modules/auth/domain/entity/auth_code.go` |
| Authorize request TTL (session cookie + cache) | 10 minutes | `AuthorizeRequestTTL` | `modules/auth/domain/entity/auth_request.go` |
| Refresh token TTL | 30 days | `RefreshTokenTTL` | `modules/auth/domain/entity/tokens.go` |
| Password reset token TTL | 15 minutes | `PasswordResetTokenTTL` | `modules/auth/domain/entity/user.go` |
| Access token default expiry | 15 minutes (900 s) | `DefaultExpirySecs` | `modules/auth/application/define/token_expiration.go` |
| Access token maximum expiry | 24 hours (86400 s) | `MaxTokenExpirySecs` | `modules/auth/application/define/token_expiration.go` |
| MongoDB TTL index on refresh tokens | at `expires_at` field | `SetExpireAfterSeconds(0)` | `modules/auth/adapter/out/mongo_refresh_token_repository.go` |

### HTTP Server

| Value | Duration | Constant | Source |
|---|---|---|---|
| Read header timeout | 5 s | `readHeaderTimeout` | `handler/web/server.go` |
| Read timeout | 30 s | `readTimeout` | `handler/web/server.go` |
| Write timeout | 30 s | `writeTimeout` | `handler/web/server.go` |
| Idle timeout | 60 s | `idleTimeout` | `handler/web/server.go` |
| Graceful shutdown timeout | 5 s | `shutdownTimeout` | `handler/web/server.go` |
| Cleanup timeout | 5 s | `cleanupTimeout` | `handler/web/server.go` |
| CORS preflight cache (`Access-Control-Max-Age`) | 12 hours | — | `handler/web/middleware/cors.go` |

### Infrastructure

| Value | Duration | Constant | Source |
|---|---|---|---|
| Redis ping timeout | 5 s | `redisPingTimeout` | `infrastructure/cache/redis.go` |
| MongoDB connect timeout | 5 s | — | `infrastructure/repository/mongo/client.go` |
| MongoDB server selection timeout | 10 s (default) | — | `infrastructure/repository/mongo/client.go` |
| SMTP dial timeout | 10 s | `dialTimeout` | `infrastructure/smtp/client.go` |
| SMTP send timeout (I/O deadline) | 30 s | `sendTimeout` | `infrastructure/smtp/client.go` |
| Mongo index creation timeout | 10 s | — | `modules/auth/adapter/out/mongo_*_repository.go` |

### Test Frontend (`cmd/backend`)

| Value | Duration | Constant | Source |
|---|---|---|---|
| Session cookie `MaxAge` | 24 hours (86400 s) | `sessionMaxAge` | `cmd/backend/main.go` |
| Token proactive refresh threshold | 1 minute before expiry | `refreshThreshold` | `cmd/backend/main.go` |
| Requested `expire_secs` sent to token endpoint | 120 s | — | `cmd/backend/main.go` |
