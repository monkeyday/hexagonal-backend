# cmd/backend browser flow (Playwright MCP)

Browser-driven smoke of the `cmd/backend` OIDC test client against the IdP,
covering the full session lifecycle. Complements the API-level `e2e/test_auth.sh`
(curl) and the `smoke_test/` (k6) suites by exercising the actual clickable UI.

**Why MCP, not the Playwright npm package:** `playwright-core` is implicated in
an active June 2026 npm supply-chain incident, so we deliberately do not install
it. The steps below are executed by an agent through the Playwright MCP browser
(its own pre-existing browser — nothing added to the repo). Revisit a committed
`@playwright/test` runner only once the package is confirmed clean.

## Run

```sh
bash e2e/backend_flow/run.sh        # starts IdP :9876 + cmd/backend :3000, then waits
```

Leave it running, drive the steps below via the MCP browser, then Ctrl-C to stop.
The IdP uses an ephemeral file store, so the test user never persists.

The forgot-password flow (steps F1–F4) needs **Mailpit** running on `:1025`
(SMTP) / `:8025` (web UI). `run.sh` auto-detects it and points the IdP's SMTP at
it; if Mailpit is down the IdP falls back to the log email sender and those
steps must be skipped.

## Fixtures

| Field | Value |
|---|---|
| Email | `playwright-flow@example.com` |
| Password | `PwTest123!` |
| Username / Nickname | `pwflowuser` / `PW Flow` |
| New password (reset) | `NewPw456!` |
| Client | `my_client2` (public, PKCE) |

## Steps

Each `cmd/backend` action returns to `/` and renders the result in the response
panel; assert against that panel unless noted.

| # | Action | Where | Assert |
|---|---|---|---|
| 1 | Create user: fill `#username/#nickname/#email/#password`, submit | `:9876/sign-up` | JSON body echoes `username`/`nickname`/`email` (HTTP 200) |
| 2 | Click **Login with IdP** → fill `#email/#password` on `/sign-in`, submit | `:3000/` → `:9876/sign-in` | lands back on `:3000/`, "Logged in", token JSON shown, `id_token` `aud=my_client2` |
| 3 | Click **UserInfo** | `:3000/` | response has `sub`, `preferred_username`, `nickname`, `email` |
| 4 | Click **Update Profile** → set Nickname `Updated Nick` → Save | `:3000/update-profile` | response `nickname` = `Updated Nick` (immediate echo) |
| 5 | Click **UserInfo** again | `:3000/` | `nickname` = `Updated Nick` — re-reads through the userinfo endpoint, proving the update **persisted server-side**, not just echoed back |
| 6 | Click **Introspect Token** | `:3000/` | **expected** `{"error":"invalid_client","error_description":"invalid_client"}` (RFC 6749 §5.2) — see note |
| 7 | Click **Refresh Token** | `:3000/` | new token JSON; `refresh_token` differs from step 2 (rotation) |
| 8 | Click **Revoke Token** | `:3000/` | returns to the logged-out home (Login button visible) |
| 9 | Click **Login with IdP**, sign in again, then click **Logout** | `:3000/` | after Logout, logged-out home is shown |

## Forgot-password flow (Mailpit)

Runs after the main flow on the same user (logged out is fine — the user still
exists in the ephemeral store). Unlike the steps above, the real assertion is
**not** a response panel: the IdP deliberately returns a generic empty `200`
whether or not the email exists (no account enumeration). Proof of correctness
comes from the **inbox** and from **logging in with the new credential** — both
independent of what any single response echoes.

| # | Action | Where | Assert |
|---|---|---|---|
| F1 | Click **Forgot Password** → enter `playwright-flow@example.com` → Send Reset Link | `:3000/forgot-password` | redirects to `:3000/` with no error (response is intentionally generic — see note) |
| F2 | Open the newest message | Mailpit `:8025` | To = `playwright-flow@example.com`, Subject `Reset your password`, body contains a `http://localhost:3000/reset-password?token=<token>` link; copy `<token>` |
| F3 | Open the reset link from the email (or **Reset Password** + paste token) → New Password `NewPw456!` → submit | `:3000/reset-password` | redirects to `:3000/` with no error |
| F4 | Click **Login with IdP**, sign in with `NewPw456!` | `:3000/` → `:9876/sign-in` | login **succeeds** — lands logged-in on `:3000/`. This is the server-side cross-check: the stored credential actually changed |
| F5 | **Logout**, then **Login with IdP** with the *old* `PwTest123!` | `:9876/sign-in` | login **fails** (stays on sign-in / error) — confirms the old password no longer works |

Token can also be pulled headlessly via `curl :8025/api/v1/message/latest` (the
`Text` field holds the body) if driving the Mailpit UI is awkward.

## Notes

- **Step 6 is a pass, not a failure.** `/oidc/introspect` requires an
  authenticated *confidential* client (RFC 7662 §2.1). `cmd/backend` is the
  *public* client `my_client2` and holds no secret, so the IdP correctly rejects
  it with `invalid_client`. It would only succeed if `cmd/backend` were
  configured as a confidential client.
- **Revoke logs you out** (`cmd/backend` clears its session on revoke), so the
  Logout button is gone afterward — step 8 re-authenticates before logging out.
- **Forgot-password returns a generic `200` by design.** `/forgot-password`
  responds identically whether or not the email maps to a real account, so an
  attacker can't probe which addresses are registered. That's why F1 asserts
  only "no error" and the meaningful checks live in F2 (the email actually
  arrived) and F4/F5 (the password actually changed). Reset also invalidates
  existing sessions and revokes refresh tokens for that user.
- The favicon `404` in the console is harmless.
