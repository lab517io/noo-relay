# AGENTS.md — noo-relay

Start with `README.md`: layout, how to run, the full v2 endpoint list, env vars, and
the SQLite schema. This file covers only what an agent changing the code needs to know
beyond that.

## What this repository is

The centralized sync relay for the Noo outliner. The Flutter client and the LAN/P2P
sync path live in the separate client repository (`noo_next` privately, published as
[lab517io/noo](https://github.com/lab517io/noo)); nothing here depends on it, and the
only contract between them is the wire protocol.

## The implementation

One Go service in `go/`, deployed to `noo.lab517.io` by `./deploy.sh`, with its own
`go/README.md`. `static/` and `docs/` sit alongside it.

It began as a port of a Python/FastAPI implementation that lived in the repository
root; that ran in production until 2026-08-30 and was removed once the Go service had
replaced it against the same database. Comments citing FastAPI are deliberate — the
wire contract is inherited from it, and they record *why* a status code or response
shape is what it is (§"Wire contract" below). `git log` has the Python source if a
question about original behaviour ever needs settling.

## Invariants — do not break these

1. **Zero knowledge.** The relay stores opaque blobs. It must never decrypt, inspect,
   validate, or merge payload content. A blob it cannot understand is not its problem.
   Any feature that requires reading a payload is a client feature by definition.
2. **No sync logic on the server.** Its whole job is authentication, ordering within a
   per-device stream, storage, and fan-out. Conflict resolution is client-side and
   deterministic — every device applies the same rules and converges.
3. **Packet identity is `(user_id, origin_device_id, counter)`**, enforced by a UNIQUE
   constraint. Counters are client-assigned, start at 1, and are contiguous per origin
   device; a re-upload of an existing identity is a no-op, and a gap is rejected. Never
   renumber a packet.
4. **The uploader need not be the origin device.** Clients gossip — they carry packets
   for their user's other devices. Authorization is per user, not per device; origin is
   verified client-side via the AEAD AAD.
5. **`stream_marks` is the next-counter authority, not `MAX(counter)`.** Compaction
   deletes low counters, so a stream can be empty and still have a top. Contiguity, the
   409 boundary and the version vector all read `max(MAX(counter), high_water)`; a mark
   is raised on every accepted packet and re-asserted before any delete. Lowering or
   forgetting a mark re-issues identities that exist elsewhere — a client-side fork
   caused by the server.
6. **Pruning is bounded by the declaration.** `X-Noo-Snapshot-Covers` is trusted (a
   client can already corrupt its own stream by lying about counters), but the relay
   deletes only at or below the declared counters, only what it holds, and never the
   uploaded snapshot itself. It never reads a payload to decide any of this.
7. **Pull ordering.** Results ascend by counter *within* each origin device so receiver
   holdings stay contiguous, and a *stream* holding an `is_snapshot` packet comes first
   so a requester starting above a pruned range can adopt coverage before the packets
   that need it. The two rank at different levels and must not be traded off: hoisting
   the snapshot *row* would lift it above the lower counters of its own device, and a
   client that then advanced its vector to that counter could never ask for what sat
   below it — packets lost to a page it can no longer request. After a prune a snapshot
   is already its stream's lowest stored counter, so ascending order puts it first
   unaided. Devices may otherwise interleave freely — the rest of the current ordering
   (`ORDER BY MAX(is_snapshot) OVER (PARTITION BY origin_device_id) DESC,
   origin_device_id, counter`) is one legal ordering, not a promise.
8. **Dependencies stay few and pinned.** `go.mod`/`go.sum` pin exact versions, and the
   build is `CGO_ENABLED=0`, so what ships is one static binary depending on nothing
   installed on the server. There are three direct dependencies — JWT, bcrypt, SQLite.
   Adding a fourth is a decision, not a convenience.

## Protocol version

Protocol v2 throughout; v1 endpoints and their tables (`changes`, `device_cursors`) are
dropped at startup. The v1→v2 migration was a deliberate epoch break: v1 blobs are
undecryptable under v2 key derivation, so clients re-announce their full current state
as fresh v2 streams rather than converting anything. Do not add back-compatibility for
v1 — v1 clients must upgrade.

`docs/RELAY_PROTOCOL.md` is the v1 specification, retained because v2 keeps its merge
semantics (§6.2, §8) unchanged. The v2 specification is `docs/P2P_SYNC.md` in the client
repository.

## Wire contract — frozen, including its warts

The v1 vocabulary survived the epoch break in the *names*, and deployed clients plus
`static/index.html` depend on it. These are not cleanups waiting to happen:

- The packet endpoints live under `/api/v2/changes/`, and the pull response field is
  `changes`, not `packets`.
- Admin responses say `change_count`, `last_change_at`, `total_changes`.
- The client-facing usage endpoint is `/api/v2/changes/usage`; its per-device rows are
  ordered largest-bytes first, which the client renders directly.

Payload transport is deliberately asymmetric: **upload** puts the raw ciphertext in the
request body with identity in headers (`X-Noo-Origin-Device`, `X-Noo-Counter`), while
**pull** returns base64 inside JSON. Do not "unify" one into the other.

Upload status codes carry meaning the client acts on — `201` slot newly filled
(`stored: true`); `200` already held, a no-op (`stored: false`, expected when a packet
arrives by more than one gossip path); `409` non-contiguous counter; `400` empty payload
or counter < 1; `413` over `NOO_MAX_PAYLOAD_SIZE`, checked against `Content-Length`
before buffering and again after the read; `422` malformed `X-Noo-Snapshot-Covers`,
which stores nothing.

A `pruned` object appears in the upload response only when the request declared
coverage — including on the `200` already-held path, so a client whose `201` was lost
still reclaims the space when it retries. Python sets `response_model_exclude_none` to
keep that body identical to Go's.

## Security model

Two separate user secrets, and the relay only ever learns about the second:

- **Database password** — encrypts the client's local SQLCipher database *and* derives
  the AES-256-GCM sync key via HKDF-SHA256. Identical across the user's devices. The
  relay never sees it.
- **Server password** — authenticates to the relay (JWT, bcrypt-hashed at rest).

| Concern | Mechanism |
|---------|-----------|
| Encryption | AES-256-GCM, client-side |
| Key derivation | HKDF-SHA256 from DB password, username as salt, info `noo-sync-v2` |
| Nonce | 12 random bytes per packet, prepended to ciphertext |
| Integrity / tamper detection | GCM 128-bit tag; `{origin_device_id}:{counter}` as AAD, so a packet re-served under any other slot fails authentication |
| Replay / duplication | UNIQUE `(user, origin device, counter)`; duplicate upload is a no-op |
| Server auth | JWT (15 min access, 30 day refresh), bcrypt password hashes |
| Username disclosure | Login answers a missing user and a wrong password identically *and in the same time* — it verifies against a dummy hash rather than returning early, or the response time would be the oracle the identical body is meant to close. `POST /auth/register` still discloses by design: 409 on a taken name is part of the wire contract |
| Admin auth | `NOO_ADMIN_TOKEN` bearer token, compared with `hmac.compare_digest` |
| Transport | HTTPS in production (nginx front, see `DEPLOYMENT.md`) |
| Account creation | Open -- `POST /auth/register` is ungated, by design. An operator who wants it closed fronts the relay with their own access control |
| Zero knowledge | Relay sees only user_id, device_id, counter, timestamp, blob, size |

Deleting a device revokes its tokens — `get_current_user` and `/auth/refresh` both
re-check that the token's device row still exists, so neither access nor refresh
survives the delete. There is a test for this; keep it passing.

## Working on the code

- Run the tests before and after any change: `go test ./...` in `go/` (74 tests), and
  `go test ./... -race` for anything touching concurrency.
- Tests drive the real router through `httptest`, no network. Each gets its own
  database in `t.TempDir()`, so the suite is safe in parallel and under `-race`.
- Servers under test are built from `config.Default()` plus explicit overrides; there is
  no settings singleton. Lower `BcryptCost` in tests — the production cost of 12
  otherwise dominates the runtime.
- Every authenticated request writes: `requireUser` updates the device's `last_seen`.
  Read-only endpoints are not read-only at the database.
- Changing the schema means changing `schemaSQL` in `go/internal/store/store.go`. It is
  applied with `CREATE TABLE IF NOT EXISTS` at startup — there is no migration
  framework, so a change to an existing table needs a hand-written idempotent step in
  `migrate()`, which runs on every start. `packets.is_snapshot` is the worked example:
  a `pragma_table_info` check and `ALTER TABLE`, alongside the one-off seed of
  `stream_marks` from `MAX(counter)`.
- Clients in the field use both the bare and trailing-slash form of every route, so
  `pair()` in `api.go` registers both. Go's ServeMux treats them as distinct patterns —
  `/x/` alone is a subtree match, and `/x` alone would 301 a POST body away. Register
  new endpoints with `pair()`.
- `static/index.html` is the admin dashboard: one hand-written file, no build step,
  reading the admin JSON field names directly. Changing an admin response shape means
  editing that file in the same commit.
- The binary serves plaintext on `0.0.0.0:8080` by default, and terminates TLS itself
  when `NOO_TLS_CERT_FILE`/`NOO_TLS_KEY_FILE` are set — which is the production shape,
  `127.0.0.1:8443` behind nginx.
- `DEPLOYMENT.md` is the public deployment guide and `docs/PRODUCTION.md` is the
  record of the live `noo.lab517.io` instance. Update whichever a change touches, in
  the same commit as anything that changes deployment shape (ports, env vars, unit
  file, paths). `docs/PRODUCTION.md` is excluded from the public snapshot -- keep
  host-specific facts in it and out of `DEPLOYMENT.md`.
- `deploy.sh` is the only supported way to ship. It tests, cross-compiles a static
  binary, snapshots the database, cuts over and health-checks — rolling back by itself
  if the check fails. Do not hand-edit the unit file on the server; change the heredoc
  in `deploy.sh` so the next deploy does not silently revert it.
- The systemd unit is written in two places: the heredoc in `deploy.sh` (the reference
  server) and `write_unit` in `install.sh` (self-hosted installs, which must stay one
  self-contained file for `curl | bash`). Change both together.
- Resource bounds are part of the relay's safety, not tuning: JSON bodies are capped at
  64 KiB (`maxJSONBody`) because `/auth` takes no credential, and a pull page stops at
  16 MiB of payload (`pullPageBytes`) as well as at `limit`. A short page still says
  `has_more`, and the client pages on that flag, not on the row count.

## Releases

The release number is `const version` in `go/cmd/relay/main.go` — the one place it is
written; `deploy.sh` reads it from there. To cut one: bump it in a commit on master,
`./deploy.sh` to production, `python scripts/publish_public.py`, then
`./deploy.sh github-release`. That builds static amd64 and arm64 tarballs (relay +
`static/`, each with a `.sha256`), attaches them and `install.sh` to GitHub release
`v<version>`, and tags the public snapshot — never master, whose history stays private.
It refuses a dirty tree, a version that is already released, and a GitHub `main` whose
code differs from master's. Asset names carry no version, so
`releases/latest/download/install.sh` always gets the newest.

## Publishing to GitHub

`scripts/publish_public.py` rebuilds `public` as one orphan commit -- master's tree
minus `PUBLIC_EXCLUDE` -- and force-pushes it to `lab517io/noo-relay` as `main`. The
real history is never published: `docs/PRODUCTION.md` was this repository's
`DEPLOYMENT.md` until the split, so it is in every commit before it, and so is the
Python service's deployment detail. Run `--dry-run` first; it names every withheld path
and refuses to build from a dirty tree. Never commit to `public` -- the next run
discards it.

Code is never withheld. A zero-knowledge claim nobody can read is not a claim.
