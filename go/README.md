# noo-relay — Go implementation

A port of the Python/FastAPI relay in the repository root. Same wire protocol,
same SQLite schema, same secrets: the two are interchangeable against one live
database, and a client cannot tell which one it is talking to.

**This is the service deployed on `noo.lab517.io`** since 2026-08-30. It replaced the
Python one in place — same database, same secrets, same nginx front — which is kept in
the repository root as the reference implementation and the rollback path.

## Why it exists

A single statically linked binary with no interpreter, no virtualenv and no
`pip install` step on the server — `CGO_ENABLED=0 go build` cross-compiles it,
and deployment is a file copy. The SQLite driver is pure Go
(`modernc.org/sqlite`), so there is no libc to match on the target.

## Layout

```
cmd/relay/          # entry point: config, signals, graceful shutdown
internal/config/    # NOO_-prefixed settings
internal/store/     # schema and every query; store.go + admin.go
internal/auth/      # JWT issue/verify and bcrypt hashing
internal/api/       # routing, middleware, handlers, the test suite
```

## Running

```bash
go build ./... && go test ./...

# from this directory; the dashboard lives at the repository root
NOO_INSECURE_DEV=1 NOO_STATIC_DIR=../static go run ./cmd/relay
```

`NOO_INSECURE_DEV=1` lets it start with the shipped placeholder secrets; without it,
the relay refuses them (see the root `README.md`).

It serves `http://0.0.0.0:8080` by default. Configuration is the same
`NOO_*` environment as the Python service (see the root `README.md`), plus:

| Variable | Default | Meaning |
|----------|---------|---------|
| `NOO_LISTEN_ADDR` | `0.0.0.0:8080` | Listen address |
| `NOO_STATIC_DIR` | `static` | Admin dashboard directory |
| `NOO_TLS_CERT_FILE` / `NOO_TLS_KEY_FILE` | unset | Serve HTTPS directly; both must be set |
| `NOO_BCRYPT_COST` | 12 | Password hashing work factor. Lower it only in tests |

Setting the TLS pair reproduces the production binding the systemd unit uses
today (uvicorn with TLS on `127.0.0.1:8443` behind nginx); leaving it unset is
the plaintext-behind-a-proxy shape.

## Tests

```bash
go test ./...            # 74 tests
go test ./... -race
```

Handlers are driven through `httptest` against the real router, with no network. Every
test gets its own database in `t.TempDir()`, so the suite is safe to run in parallel and
under `-race`.

The suite is the Python suite's 30 tests plus six covering ports risks that do
not exist in FastAPI: bare-vs-trailing-slash routing, `limit` validation on the
pull endpoint, refresh rejecting an access token, admin token enforcement, the
admin stats field names, and registration field limits.

## Inherited wire behaviour

The service replaced a Python/FastAPI implementation and kept its wire contract
verbatim, which is why several handlers carry comments citing FastAPI. Those are the
rationale for choices that would otherwise look arbitrary:

- errors are `{"detail": "..."}`, FastAPI's envelope;
- a missing or malformed credential is `401 Not authenticated` with a
  `WWW-Authenticate: Bearer` challenge, while a *valid* bearer token that is not the
  admin token is `403` — the split FastAPI's `HTTPBearer` produced;
- schema-validation failures are `422`, distinct from the `400`s handlers raise
  deliberately.

Four behaviours were deliberately changed at the port, and are worth knowing because
they are the only places the current service differs from what those comments describe:

| Case | Before | Now |
|------|--------|-----|
| `GET /api/v2/devices` and `/api/v2/changes` without the trailing slash | 307 redirect | 200 direct — both forms registered, strictly more permissive |
| Admin lists when two rows share a `created_at`/`last_seen` second | order left to the query plan | newest first, `id` breaking the tie |
| 422 bodies | array of Pydantic error objects | `{"detail": "<message>"}` |
| Access log | uvicorn's format | `slog` key/value lines |

While both implementations existed they were checked against each other by an interop
run (tokens, password hashes and packets crossing between them against one database)
and a differential run (an identical request sequence against both, diffing every
status code and body). Both passed; the harnesses retired with the Python source.

## Deploying

`../deploy.sh` from the repository root — it tests, cross-compiles, snapshots the
database, cuts over and health-checks, rolling back on its own if the check fails.

```bash
../deploy.sh            # build, back up, deploy, verify
../deploy.sh build      # cross-compile only
../deploy.sh status     # what is running right now
../deploy.sh rollback   # restore the previous unit
../deploy.sh release    # amd64 + arm64 tarballs and install.sh, into build/release/
../deploy.sh github-release   # the same, attached to GitHub release v<version>
```

The database needed no migration: the schema is identical, and the cutover reused the
production file as it was. `DEPLOYMENT.md` at the repository root describes the live
setup; update it in the same commit as anything that changes deployment shape.
