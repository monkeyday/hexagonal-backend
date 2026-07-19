# Stress / load suite (k6)

Load and capacity tests for the auth server. Distinct from `smoke_test/`, which
is correctness-only (1 VU, 1 iteration). These run many concurrent VUs over time.

## Running

The server **must** run with rate limiting disabled, or the single load-generator
IP is throttled:

```sh
RATE_LIMIT_PER_MIN=0 ./bin/auth
```

Then run a scenario (override scale with `-e`):

```sh
k6 run stress_test/userinfo.js
k6 run -e VUS=80 -e DURATION=3m stress_test/mixed.js
k6 run -e BASELINE=20 -e SPIKE=300 stress_test/spike.js
```

Run against **MongoDB + Redis**, not file/in-memory, for representative numbers.
The CI workflow (`.github/workflows/stress.yml`, manual `workflow_dispatch`) wires
both as service containers. Mongo requires credentials (`MONGO_USER` /
`MONGO_PASSWORD` / `MONGO_AUTH_SOURCE`) — the config validator rejects a no-auth
Mongo.

## Layout

- `helpers.js` — low-level request helpers, `rampingScenario`, `perEndpointThresholds`.
- `actions.js` — per-VU actions on a lazily-minted session (`doUserinfo`,
  `doRefresh`, `doLogin`, `doDiscovery`, `doMixedIteration`) + the mixed-workload
  threshold map. Each VU owns a unique user (`load_user_${__VU}@example.com`);
  sharing a user breaks under concurrency (refresh reuse detection #6, account
  lockout #8).
- `*.js` scenarios — thin wrappers selecting a workload and stage profile:
  `token_refresh`, `userinfo`, `auth_code_flow`, `mixed`, `spike`, `soak`.

## Thresholds & calibration

Per-endpoint p95 thresholds are **regression guardrails, not SLOs**. They are set
at roughly 6x the baseline p95 below — generous enough to tolerate slower hardware
and contention, tight enough to catch a gross regression.

`P95_MAX` overrides every per-endpoint p95. CI sets it generously
(`P95_MAX=5000`) because shared GitHub runners are noisy and the baseline below is
not from production hardware — so CI gates on correctness (checks +
`http_req_failed`), not latency.

### Baseline snapshot

Captured on a dev workstation (Apple silicon) against Dockerized MongoDB + Redis,
`RATE_LIMIT_PER_MIN=0`. Worst-observed p95 across an isolated run and a 40-VU
`mixed` run (whichever was higher):

| Endpoint        | baseline p95 | guardrail p95 | notes                 |
|-----------------|-------------:|--------------:|-----------------------|
| `userinfo`      |        26 ms |        150 ms | authenticated read    |
| `discovery`     |        10 ms |        150 ms | cacheable read        |
| `authorize`     |         9 ms |        300 ms | session create        |
| `refresh_reuse` |         6 ms |        300 ms | rejected reuse        |
| `refresh`       |        51 ms |        300 ms | Mongo rotation write  |
| `token_code`    |        38 ms |        300 ms | code exchange         |
| `password`      |        80 ms |        500 ms | password hashing      |
| `sign_in`       |        96 ms |        500 ms | password hashing      |

`spike.js` keeps a flat, looser p95 (degradation is expected during a surge) and
allows `http_req_failed` up to 5%.

### Still pending

Recalibrate against a **production-representative** environment, then tighten the
guardrails to real SLOs and drop `P95_MAX` from the CI workflow so CI also gates
on latency. Until then the numbers above are a dev-workstation reference only.
