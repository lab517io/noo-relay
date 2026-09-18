# noo-relay

The centralized sync relay for the [Noo](https://github.com/lab517io/noo) outliner —
a Go **zero-knowledge** store-and-forward mailbox for encrypted sync packets.

The relay never sees plaintext. Clients upload opaque AES-256-GCM blobs; the relay
authenticates, stores, and fans them out. All encryption, decryption, packaging, and
conflict resolution happen client-side. A relay operator with full database access
learns only *who* syncs, *how often*, and *how much* — never *what*.

This repository holds the server only. The Flutter client lives in
[lab517io/noo](https://github.com/lab517io/noo); the LAN/P2P sync path is
entirely client-side and lives there too.

## Protocol

Protocol **v2**: per-device packet streams with client-assigned contiguous counters,
and version-vector exchange. There is no server-assigned global sequence — a user's
sync state is the version vector: the highest counter ever accepted per origin device.
Any node may carry packets for any other device of the same user (gossip), so any
connectivity path eventually converges.

**v2.1 adds compaction.** A client may publish a full-state snapshot and declare, in
`X-Noo-Snapshot-Covers`, which packets it supersedes; the relay deletes them. Per-device
high-water marks are persisted (`stream_marks`) so a pruned stream continues at its old
counter instead of restarting at 1, and the vector still names the top of every stream
whether or not those packets are still stored.

- `docs/RELAY_PROTOCOL.md` — v1 spec, superseded, retained because v2 references its
  merge semantics unchanged.
- [`docs/P2P_SYNC.md`](https://github.com/lab517io/noo/blob/main/docs/P2P_SYNC.md)
  in the client repository — the current v2 specification.
- `docs/P2P_SYNC_COMPACTION.md` in the client repository — v2.1 compaction.

v1 endpoints are gone; the v1→v2 migration was a clean epoch break.

## Layout

```
go/
├── cmd/relay/       # entry point: config, signals, graceful shutdown
├── internal/
│   ├── api/         # routing, middleware, handlers, tests
│   ├── auth/        # JWT + bcrypt
│   ├── config/      # settings, NOO_-prefixed env vars
│   └── store/       # SQLite schema and every query
└── README.md        # build, test, deploy, verification
static/              # Admin dashboard (single-page HTML/JS)
docs/                # Protocol specifications
deploy.sh            # Build and deploy to noo.lab517.io
```

The service was originally Python/FastAPI, which ran in production until 2026-08-30 and
was removed once the Go implementation had replaced it against the same database. The
wire contract is inherited from it unchanged; `git log` has the source.

## Running

```bash
cd go
go build ./... && go test ./...
NOO_INSECURE_DEV=1 NOO_STATIC_DIR=../static go run ./cmd/relay   # http://0.0.0.0:8080
go run ./cmd/relay -version
```

Environment variables (prefix `NOO_`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `NOO_DATABASE_URL` | `noo_sync.db` | SQLite file path |
| `NOO_JWT_SECRET` | `change-me-in-production` | JWT signing secret — **must** be overridden |
| `NOO_ADMIN_TOKEN` | `change-me-admin-token` | Admin API/dashboard token — **must** be overridden |
| `NOO_MAX_PAYLOAD_SIZE` | 10 MB | Max packet upload size in bytes |
| `NOO_ACCESS_TOKEN_EXPIRE_MINUTES` | 15 | Access token lifetime |
| `NOO_REFRESH_TOKEN_EXPIRE_DAYS` | 30 | Refresh token lifetime |
| `NOO_LISTEN_ADDR` | `0.0.0.0:8080` | Listen address |
| `NOO_STATIC_DIR` | `static` | Admin dashboard directory |
| `NOO_TLS_CERT_FILE` / `NOO_TLS_KEY_FILE` | unset | Serve HTTPS directly; both must be set |
| `NOO_BCRYPT_COST` | 12 | Password hashing work factor — lower only in tests |
| `NOO_INSECURE_DEV` | unset | `1` accepts the shipped secrets, for local runs only |

The relay refuses to start if either secret is still at its shipped default or shorter
than 32 characters (`openssl rand -hex 32` makes a good one), unless `NOO_INSECURE_DEV=1`.

The release number is `version` in `go/cmd/relay/main.go`; `relay -version` prints it
with the commit, and `/health` reports it.

## Tests

```bash
cd go && go test ./...        # 74 tests
cd go && go test ./... -race
```

74 tests covering registration, login, token refresh, packet upload/download,
version-vector filtering, gap rejection, carried (gossip) packets, device management,
token revocation on device deletion, auth/payload failure paths, and compaction
(pruning, mark persistence, snapshot-first pulls and the per-device ascent they must
not break, usage reporting), stream hashes, attachment blobs, request and pull-page
size bounds, and the refusal of weak secrets.

## API

All endpoints are under `/api/v2/`. Auth is JWT: 15-minute access token, 30-day refresh,
payload `{sub: user_id, device_id, type}`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/auth/register` | Create an account |
| POST | `/api/v2/auth/login` | Log in, register the device, get tokens |
| POST | `/api/v2/auth/refresh` | Refresh the access token |
| GET | `/api/v2/devices/` | List the user's devices |
| POST | `/api/v2/devices/` | Register a device |
| DELETE | `/api/v2/devices/{device_id}` | Remove a device (revokes its tokens) |
| GET | `/api/v2/changes/vector` | The relay's version vector for this user |
| POST | `/api/v2/changes/` | Upload one packet (`X-Noo-Origin-Device`, `X-Noo-Counter` headers; optional `X-Noo-Snapshot-Covers`) |
| GET | `/api/v2/changes/?have={json}&limit={n}` | Pull everything above the caller's vector, snapshots first |
| GET | `/api/v2/changes/usage` | This account's stored bytes and packets, per origin device |
| GET | `/health` | Health check |
| GET | `/admin/` | Admin dashboard (static) |

Admin API under `/api/v2/admin/`, all requiring `Authorization: Bearer <NOO_ADMIN_TOKEN>`:
`GET /stats`, `GET|POST /users`, `DELETE /users/{id}`, `GET /users/{id}/devices`,
`GET /users/{id}/changes`.

## Storage

SQLite, WAL, foreign keys on:

- **users** — id, username, password_hash (bcrypt), created_at
- **devices** — id, user_id, device_id (UUID), device_name, platform, created_at, last_seen; unique per (user, device)
- **packets** — id, user_id, origin_device_id, counter, payload (BLOB), stored_at, is_snapshot; unique per (user, origin device, counter)
- **stream_marks** — user_id, origin_device_id, high_water; the highest counter ever
  accepted per stream, kept across pruning so a compacted stream never restarts at 1

## Install on your own server

On any Linux server with systemd (amd64 or arm64):

```bash
curl -fsSL https://github.com/lab517io/noo-relay/releases/latest/download/install.sh | sudo bash
```

It creates the `noosync` user, `/opt/noo-sync`, `/var/lib/noo-sync` and
`/etc/noo-sync.env` with freshly generated secrets, installs the systemd unit, starts
the relay, checks its health and prints the admin token. The relay listens on
`127.0.0.1:8080`; put a TLS reverse proxy (Caddy, nginx) in front. Settings go after
`sudo` — e.g. `sudo NOO_LISTEN_ADDR=0.0.0.0:8080 bash`, or `NOO_VERSION=1.0.0` to pin a
release; the header of `install.sh` lists them all.

Re-running the same command upgrades in place: the database and secrets are kept, the
previous binary is saved as `relay.prev`, and a release that fails its health check is
rolled back automatically.

## Deployment

`DEPLOYMENT.md` — how to run your own: build, secrets, TLS, the systemd unit,
`deploy.sh`, backups, and a checklist before pointing clients at it.

The client does not ship a default server: *Preferences → Sync* has an empty
Server URL, and an empty one means sync only with your own devices on the same
network. Point it at your relay to also sync when they are apart.
`https://noo.lab517.io` is the instance this project runs, if you would rather
not host one.

## License

MIT — see [LICENSE](LICENSE). Run your own relay; that is the point of it being
readable.
