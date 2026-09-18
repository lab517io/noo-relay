# Deploying a Noo relay

How to run your own relay. Nothing here is specific to any one installation —
`docs/PRODUCTION.md` in the private repository records how the instance at
`noo.lab517.io` is actually set up, and is not part of this snapshot.

You need a Linux host with a domain name pointed at it, and Go on your own
machine. Nothing needs installing on the server: the binary is statically
linked (`CGO_ENABLED=0`) and the SQLite driver is pure Go, so there is no
interpreter, no virtualenv and no libc to match.

## What the relay is, operationally

One process, one SQLite file. It authenticates users, stores opaque encrypted
packets under `(user, origin device, counter)`, and serves them back to that
user's other devices. It cannot read anything it stores, so an operator's
obligations are narrower than usual: keep the database intact, keep the two
secrets secret, and keep TLS working. There is nothing to decrypt and nothing
to moderate.

## The quick way

On a Linux server with systemd, one command installs a prebuilt release — user,
directories, generated secrets, the hardened unit below — and starts it:

```bash
curl -fsSL https://github.com/lab517io/noo-relay/releases/latest/download/install.sh | sudo bash
```

It binds `127.0.0.1:8080` for a reverse proxy; the TLS section below still applies.
Re-run it to upgrade. The rest of this document is the manual route, and what
`deploy.sh` does for a server you build for yourself.

## Build

```bash
cd go
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ../build/relay ./cmd/relay
```

`./deploy.sh build` does the same thing, and asserts the result is actually
statically linked before it will ship it.

## Configuration

Every setting is a `NOO_`-prefixed environment variable; the full table is in
`README.md`. Two of them have shipped defaults that are sentinels, not values:

| Variable | Why it matters |
|----------|----------------|
| `NOO_JWT_SECRET` | Signs session tokens. Left at its default, anyone who reads this repository can forge a token for any account. |
| `NOO_ADMIN_TOKEN` | Guards the admin API and dashboard, which can list and delete users. |

Generate both, and never reuse them between installations:

```bash
openssl rand -base64 32
```

The relay refuses to start if either is still at its shipped default, or shorter
than 32 characters. `NOO_INSECURE_DEV=1` overrides that for running on your own
machine; never set it on a reachable server.

Changing `NOO_JWT_SECRET` later invalidates every issued token, so all clients
must log in again. That is the correct move if it has leaked, and a gratuitous
annoyance otherwise.

## TLS

Two supported shapes. Both are production shapes; pick one.

1. **Terminate in the relay.** Set `NOO_TLS_CERT_FILE` and `NOO_TLS_KEY_FILE`
   (both, or neither) and let it serve HTTPS directly.
2. **Plaintext behind a reverse proxy.** Leave the TLS pair unset and bind
   `NOO_LISTEN_ADDR` to loopback.

The binary reads its certificate **once, at startup**. Under any automatic
renewal the service must therefore be restarted when the certificate changes,
or it keeps serving the expired one until something else restarts it. With
certbot, that is a deploy hook that copies the new pair where the service user
can read it and then restarts the unit — not a reload.

If you put a reverse proxy in front, its body-size limit must exceed the
relay's own, or the proxy answers `413` with its own error page before the
relay can return the JSON error that explains the limit. The relevant ceilings
are `NOO_MAX_PAYLOAD_SIZE` (one sync packet, 10 MB default) and
`NOO_MAX_BLOB_SIZE` (one attachment, 64 MB default); nginx's default of 1 MB
rejects valid uploads. Sync pushes can also be large and slow on poor links, so
raise the proxy's send and read timeouts well above their defaults.

## Layout on the server

`deploy.sh` creates and expects this layout. The paths are hardcoded in that
script rather than configurable — change them there if you want others:

| Thing | Path |
|-------|------|
| Binary | `/opt/noo-sync/relay` |
| Previous binary | `/opt/noo-sync/relay.prev` (one-step rollback) |
| Admin dashboard | `/opt/noo-sync/static/` |
| Config and secrets | `/etc/noo-sync.env` (`root:noosync`, `0640`) |
| Database | `/var/lib/noo-sync/noo_sync.db` |
| Deploy backups | `/root/noo-deploy/` |
| systemd unit | `/etc/systemd/system/noo-sync.service` |
| Service user | `noosync` (system user, no login, no shell) |

The unit file is generated from a heredoc in `deploy.sh` on every deploy. That
is deliberate: hand-edit it on the server and the next deploy silently reverts
your change. Edit the heredoc instead. It runs the service as `noosync` under
`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes` and
`PrivateTmp=yes`, with `/var/lib/noo-sync` as the only writable path.

## Deploying

```bash
export NOO_DEPLOY_HOST=root@relay.example.com
export NOO_PUBLIC_URL=https://relay.example.com

./deploy.sh            # test, build, back up, cut over, verify
./deploy.sh build      # cross-compile only, into build/
./deploy.sh status     # what is running right now
./deploy.sh rollback   # restore the previous binary and restart
```

One cutover does: run the tests, cross-compile, take a hot `sqlite3 .backup`,
upload the binary and dashboard, stop the service, take a cold copy of the
database, swap the binary, start, then poll `/health` for twenty seconds. **If
the health check fails it rolls back by itself** and leaves the previous binary
running.

It never touches the database, the secrets in the env file, the reverse proxy
config, or the certificates.

The cold copy takes the `-wal` and `-shm` files along with the main file. In WAL
mode the main file alone is only as current as the last checkpoint, so copying
it by itself would drop recent commits in exactly the case the copy exists
for — a stop that did not close cleanly.

`rollback` is one deploy backwards: every deploy keeps the outgoing binary as
`relay.prev`, so it always undoes the most recent one and no more.

## Creating the first account

Registration is **closed** by default: `POST /auth/register` answers `403`, and
accounts are created by the operator — from the admin dashboard at `/admin/`
(it logs in with `NOO_ADMIN_TOKEN`), or with the admin API:

```bash
curl -X POST https://relay.example.com/api/v2/admin/users \
  -H "Authorization: Bearer $NOO_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"you","password":"a-strong-password"}'
```

Username 3–50 characters, password at least 8.

Set `NOO_REGISTRATION=open` to let anyone who can reach the relay sign up —
from the Noo client (*Preferences → Sync*, then **Register**) or with the same
request against `/api/v2/auth/register/`. If you do, set `NOO_USER_QUOTA_BYTES`
too: an open relay is otherwise free disk for whoever finds it.

## Abuse limits

On by default, and none needs tuning for a handful of users:

- **Login and register** are limited per client IP (`NOO_AUTH_RATE_PER_MINUTE`,
  20), and failed logins per *username* back off — five free failures, then
  waits doubling from 1 s to 5 min — so guesses spread over many addresses
  gain nothing. Refresh is never limited: the client drops its tokens when a
  refresh fails. At most `NOO_MAX_CONCURRENT_HASHES` bcrypt checks run at once.
- **Behind a reverse proxy**, set `NOO_TRUSTED_PROXIES` to the proxy's address
  (`127.0.0.1,::1` for a local one) and have it send `X-Forwarded-For`.
  Otherwise every client shares the proxy's single login budget.
- **Storage**: `NOO_USER_QUOTA_BYTES` (off by default), `NOO_MAX_STREAMS_PER_USER`
  (256), and `NOO_MIN_FREE_DISK_BYTES` (256 MB), all answering `507`. They
  apply to new data only; re-sending what the relay already holds always works,
  and a compaction snapshot is credited with what it frees.

### The two secrets users have to keep straight

This confuses people, and the relay cannot help them with it:

- **Database password** — encrypts the client's local database *and* derives
  the end-to-end sync key. It must be **identical on every device** a user
  syncs, or those devices cannot read each other's packets. The relay never
  sees it and cannot reset it.
- **Server password** — authenticates to the relay, nothing more. Resettable,
  because the relay does hold it (bcrypt-hashed).

## Backing up

The whole service state is one SQLite file. Take it with `.backup`, not `cp`, on
a running service:

```bash
ssh root@relay.example.com \
  'sqlite3 /var/lib/noo-sync/noo_sync.db ".backup /root/noo_sync_backup.db"'
```

A deploy leaves both a hot and a cold snapshot in `/root/noo-deploy/`, which
accumulate — prune them on whatever schedule your disk demands.

Restoring gives users back their packets, which is all the relay ever had. It
cannot restore anything a client did not upload, and it cannot decrypt what it
does restore.

## Checklist before you point clients at it

```bash
curl -s  https://relay.example.com/health                      # {"status":"ok"}
curl -so /dev/null -w '%{http_code}\n' https://relay.example.com/admin/
ssh root@relay.example.com 'systemctl is-enabled noo-sync'      # enabled
ssh root@relay.example.com 'journalctl -u noo-sync -n 30 --no-pager | grep -i warn'
```

- Both secrets generated — the relay will not start otherwise — and
  `NOO_INSECURE_DEV` absent from the env file.
- Behind a proxy: `NOO_TRUSTED_PROXIES` set, and the proxy sends
  `X-Forwarded-For`.
- Registration closed, or open with a `NOO_USER_QUOTA_BYTES`.
- `systemctl is-enabled noo-sync` says `enabled`, so it survives a reboot.
- Certificate renewal restarts the unit rather than reloading it.
- The reverse proxy's body limit is above `NOO_MAX_BLOB_SIZE`.
- Something backs up `/var/lib/noo-sync/noo_sync.db` on a schedule.
- The env file is `0640`, owned `root:<service group>`, and the database
  directory is not world-readable. The blobs are encrypted, but the user names,
  device names and sync timings in that file are not.
