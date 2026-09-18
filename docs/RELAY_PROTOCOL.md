# Noo Sync Relay Protocol (v1 — superseded)

> **Superseded by protocol v2** — per-device packet streams, version-vector
> exchange, and LAN peer sync; see `docs/P2P_SYNC.md` in the client
> ([`lab517io/noo`](https://github.com/lab517io/noo)) repository. This document remains as
> the specification of the retired v1 wire format and of the merge semantics
> (§6.2, §8) that v2 references and keeps unchanged.

This document specifies the protocol between the Noo client and the sync relay
server: the wire format, the cryptographic envelope, sequence and
cursor semantics, and the full client sync cycle including conflict resolution.

It describes protocol **version 1** (`SyncPacket.version = 1`, HKDF info string
`noo-sync-v1`), as implemented in:

- Server: the FastAPI/SQLite implementation formerly at `app/` in this
  repository, removed 2026-08-30 and available in `git log`
- Client (in the [client](https://github.com/lab517io/noo) repository):
  `client/lib/data/services/sync_service.dart`, `sync_api_client.dart`,
  `sync_crypto.dart`, `sync_change_packager.dart`,
  `client/lib/domain/entities/sync_packet.dart`

---

## 1. Design overview

The relay is a **zero-knowledge store-and-forward mailbox**. It never sees
plaintext user data and contains no sync logic:

- Clients upload **opaque encrypted blobs** ("changes"). The server assigns each
  blob a **monotonic per-user sequence number** and stores it verbatim.
- Clients download blobs *from other devices* in sequence order and merge them
  locally.
- All encryption, decryption, packaging, and conflict resolution happen
  **client-side**. The server's only jobs are authentication, ordering, storage,
  and fan-out.

Consequences of this design:

- The server cannot read, validate, or merge content. A blob it cannot
  understand is not its problem — clients must tolerate undecryptable blobs
  (see §7.3).
- Conflict resolution is deterministic and symmetric: every device applies the
  same field-level Last-Writer-Wins rules (§8), so all devices converge without
  server coordination.
- Changes are **full current values, not diffs** (§6.2), so a lost or skipped
  blob degrades to stale data, not corruption.

## 2. Terminology

| Term | Meaning |
|------|---------|
| **User** | An account on the relay (username + server password). All devices of a user share one change stream. |
| **Device** | A client installation, identified by a client-generated UUID (`device_id`). |
| **Change (blob)** | One encrypted, gzip-compressed `SyncPacket` uploaded by a device. The unit of storage and transfer. |
| **Sequence** | Monotonic per-user integer assigned by the server to each uploaded blob. Defines the total order of the stream. |
| **Client cursor** | `sync_last_sequence` property in the client database: the highest sequence this device has processed. Drives pulls. |
| **Server cursor** | `device_cursors.last_sequence` row on the server. Updated as a side effect of pulls; **informational only** (admin dashboard). The client never reads it. |
| **Watermark** | Per-table history row-id (`sync_pushed_*_hid` properties) in the client database marking what has already been pushed. |
| **SyncPacket** | The plaintext JSON payload inside a blob: a batch of field-level changes from one device (§6.2). |

## 3. Transport and authentication

All communication is HTTPS + JSON (except change upload, which is a raw binary
body). Base path: `{serverUrl}/api/v1/`.

### 3.1 Two passwords

Sync involves two independent secrets:

- **Server password** — authenticates the account to the relay (bcrypt-hashed
  server-side, first 72 bytes considered). Knows nothing about content.
- **Database password** — the local SQLCipher password; also the input to the
  sync encryption key (§5). **Never sent to the server.**

A relay compromise therefore exposes only ciphertext, usernames, device
metadata, timing, and blob sizes.

### 3.2 JWT session

`POST /auth/login` returns an **access token** (15 min, default) and a
**refresh token** (30 days, default), both HS256 JWTs with payload
`{sub: <user_id>, device_id: <uuid>, type: "access"|"refresh", exp: ...}`.

Client behavior (`SyncApiClient`):

- Tokens are held in memory only; a fresh login happens at most once per app
  session (skipped while a cached token exists).
- On any 401, the client tries `POST /auth/refresh` once and retries the
  request. If refresh also fails, tokens are dropped so the next sync cycle
  performs a fresh username/password login.

Server behavior:

- `/auth/refresh` re-verifies that both the user **and the token's device**
  still exist, so a revoked device cannot mint tokens forever.
- Login registers the device if unknown (creating its server cursor at 0) or
  updates its name/platform/last_seen if known.

## 4. Server data model

SQLite, one database (`noo_sync.db` by default):

- **users**: `id`, `username`, `password_hash` (bcrypt), `created_at`,
  `next_sequence` — the per-user sequence counter.
- **devices**: `id`, `user_id`, `device_id` (UUID), `device_name`, `platform`,
  `created_at`, `last_seen`.
- **changes**: `id`, `user_id`, `device_id` (origin), `sequence`, `payload`
  (BLOB, opaque), `timestamp` (server receive time, UTC).
- **device_cursors**: `user_id`, `device_id`, `last_sequence`.

Changes are never deleted by the protocol (a new device replays the full stream
from sequence 0). Deleting a user (admin API) removes all their data.

## 5. Cryptographic envelope

Implemented in `SyncCrypto` (client-only; the server never touches this layer).

### 5.1 Key derivation

One symmetric key per (database password, username) pair, derived fresh at the
start of every sync cycle:

```
key = HKDF-SHA256(
    ikm  = utf8(database_password),
    salt = utf8(username),
    info = utf8("noo-sync-v1"),
    len  = 32 bytes
)
```

All of a user's devices must be opened with the same database password, or they
will be unable to decrypt each other's blobs (such blobs are skipped, §7.3).
Changing the database password effectively starts a new crypto epoch: blobs
uploaded before the change become undecryptable to devices using the new key.

### 5.2 Blob format

Each uploaded payload is:

```
AES-256-GCM(
    plaintext = gzip(utf8(SyncPacket JSON)),
    key       = derived key,
    nonce     = 12 random bytes,
    aad       = utf8(origin device_id)
)

wire blob = nonce (12 bytes) || ciphertext || GCM tag (16 bytes)
```

The **AAD is the uploading device's `device_id`** — the same string the server
returns as `device_id` alongside each downloaded blob. This binds the
ciphertext to its claimed origin: a blob replayed under a different device_id
fails authentication. Decryption must use the `device_id` field from the
download response as AAD.

## 6. Wire format

### 6.1 REST API

All sync endpoints except register/login/refresh require
`Authorization: Bearer <access_token>`.

| Method | Path | Body | Success | Notes |
|--------|------|------|---------|-------|
| POST | `/auth/register` | `{username (3–50), password (8–128)}` | 201 | 409 if username taken |
| POST | `/auth/login` | `{username, password, device_id, device_name, platform}` | 200 `{access_token, refresh_token, token_type}` | Registers/updates device |
| POST | `/auth/refresh` | `{refresh_token}` | 200 (new token pair) | 401 if invalid/expired or device deleted |
| POST | `/changes/` | raw `application/octet-stream` blob | 201 `{sequence}` | 400 empty, 413 over `NOO_MAX_PAYLOAD_SIZE` (10 MB default) |
| GET | `/changes/?since={seq}&limit={n}` | — | 200 `{changes: [...], has_more}` | `limit` 1–1000, default 100 |
| GET | `/devices/` | — | 200 `[{device_id, device_name, platform, created_at, last_seen}]` | |
| POST | `/devices/` | `{device_id, device_name, platform}` | 201 | 409 if already registered; login usually makes this unnecessary |
| DELETE | `/devices/{device_id}` | — | 204 | 400 if it is the calling device |
| GET | `/health/` | — | 200 | Unauthenticated connectivity check |

Each element of `changes` in the pull response:

```json
{
  "sequence": 42,
  "timestamp": "2026-07-04T12:00:00Z",   // server receive time
  "payload": "<base64 of the encrypted blob>",
  "device_id": "<origin device UUID>"     // use as AAD for decryption
}
```

Pull semantics (server side):

- Returns changes with `sequence > since`, ascending, **excluding the calling
  device's own uploads** (a device never sees its own blobs back).
- Fetches `limit + 1` rows internally; `has_more = true` means another page
  exists. Sequences in a response are **not necessarily contiguous** (own-device
  rows are filtered out) — clients must resume from the last *returned*
  sequence, not `since + limit`.
- As a side effect, upserts the server cursor to the highest returned sequence
  (monotonic — never moves backward).

### 6.2 SyncPacket (plaintext payload)

The decrypted, decompressed payload is JSON:

```json
{
  "version": 1,
  "device_id": "<origin device UUID>",
  "timestamp": "<ISO-8601 UTC, packet creation time>",
  "changes": [
    {
      "entity_type": "task" | "file" | "timeline",
      "world_id": "<globally unique entity id, shared across devices>",
      "field": "<field name, see below>",
      "value": "<full current value as string, or null>",
      "timestamp": "<ISO-8601 UTC — origin edit time; the LWW clock>",
      "is_creation": false,
      "parent_world_id": "<world_id of owning entity, optional>"
    }
  ]
}
```

Key semantics:

- **One change = one field of one entity.** Entities are identified by
  `world_id` (a UUID shared by all devices), never by local row ids.
- **`value` is the full current value, not a diff.** Numbers/flags are
  stringified; `file.content` is base64; task `parentId` carries the parent's
  `world_id` (null/empty = root).
- **`timestamp` is the origin edit time** (from the local history table), not
  upload time. It is the clock used for Last-Writer-Wins (§8.1).
- **`is_creation`** marks that this entity's history includes its creation, so
  the receiver may materialize a missing entity. The flag is carried forward
  through coalescing (a create + rename coalesces to one change that is still
  `is_creation: true`).
- **`parent_world_id`**: for tasks, the parent task; for files and timeline
  records, the owning task. Files and timeline records cannot be created
  without a resolvable owning task.

Per-entity fields:

| Entity | Fields |
|--------|--------|
| `task` | `title`, `content`, `parentId`, `orderId`, `flags`, `removed` |
| `file` | `filename`, `content` (base64), `orderId`, `removed` |
| `timeline` | `taskId` (owning task's world_id), `startTime`, `endTime`, `removed` |

`removed` is `"1"`/`"0"` — deletions are soft and sync as ordinary field
changes (and can be undone by a later `removed: "0"`, except timeline records,
which only honor `removed: "1"`).

## 7. The sync cycle (client)

`SyncService.performSync()` runs four stages in order; the cycle is
non-reentrant (an overlapping trigger is rejected). A full cycle is
**push-then-pull**; there is no server push — pull happens on manual sync and
on the auto-sync timer (configurable interval).

### 7.1 Prepare and authenticate

1. Derive the sync key (§5.1). Requires a password-protected database.
2. If no valid cached token exists, `POST /auth/login`.

### 7.2 Push

1. Read the three per-table push watermarks (`sync_pushed_task_hid`,
   `sync_pushed_file_hid`, `sync_pushed_timeline_hid`) — history **row ids**,
   not wall-clock times, so edits made *during* a previous sync are never
   dropped behind a completion-time watermark.
2. Collect local history rows with `id > watermark` (remote-applied rows are
   marked and excluded — applying remote changes never re-pushes them).
3. **Coalesce** to one change per `entityType:worldId:field`, keeping the
   latest, resolving the **full current value** from the database, and
   preserving `is_creation` if any coalesced-away row was a creation.
4. Build one `SyncPacket`, serialize → gzip → encrypt (§5.2) → `POST /changes/`.
5. **Only after a successful upload**, advance each watermark to the max row id
   seen for its table. A failed upload leaves watermarks untouched, so the same
   changes are re-sent next cycle (safe: re-applying full values under LWW is
   idempotent).

A whole cycle's local edits travel as **one blob** regardless of change count.

### 7.3 Pull and apply

1. Read the client cursor `sync_last_sequence` (0 for a fresh device — which
   therefore replays the entire stream).
2. Loop: `GET /changes/?since={cursor}&limit=100` until `has_more` is false.
3. For each returned blob: base64-decode → decrypt with AAD = the response's
   `device_id` (§5.2) → gunzip → parse `SyncPacket` → apply each change (§8).
4. **A blob that fails to decrypt or parse is skipped**, its sequence recorded
   for diagnostics (`SyncService.skippedBlobs`). One corrupt blob must not
   wedge the stream.
5. The cursor is advanced and **persisted after every blob**, applied or
   skipped, so an interruption mid-page neither reprocesses nor gets stuck on
   earlier blobs. Because the cursor is per-device client state, each device
   independently walks the same stream.

### 7.4 Completion

A row is written to the local sync log (success or failure), and the raw
field-level changes are summarized per-entity for the UI details view.

## 8. Conflict resolution (client-side)

### 8.1 Field-level Last-Writer-Wins

For each incoming change, the client looks up the timestamp of the latest
history row (local or previously-applied remote) for that **entity + field**:

- No history for the field → **remote wins**.
- Otherwise remote wins iff `remote.timestamp > local.timestamp` (strict;
  ties → local wins).

Granularity is the individual field: device A editing a task's title and
device B editing the same task's content merge cleanly; only same-field edits
conflict, and the newer origin-time edit wins on every device. This depends on
reasonably accurate device clocks (see §10).

Applied remote values are written with the change's **origin timestamp** and
marked remote, so they neither distort future LWW comparisons nor get pushed
back out.

### 8.2 Entity creation

If the target `world_id` doesn't exist locally:

- `is_creation: false` → skip (an update to an entity we never saw; its
  creation is elsewhere in the stream or was lost).
- `is_creation: true` → create a **bare, history-free row** stamped with the
  change's origin timestamp, then apply the triggering field normally. Because
  the bare row records no field history, sibling field changes for the new
  entity all apply cleanly instead of losing LWW to a spurious "now()" stamp.
- If a sibling change in the same packet already created the entity, fall
  through to the normal LWW update path.

Parent resolution: a task with an unresolvable `parent_world_id` is created at
root. Files and timeline records **require** a resolvable owning task and are
otherwise skipped. Timeline creation seeds a placeholder `startTime` (the real
one overwrites it via LWW).

### 8.3 Structural safety

Applying a remote `parentId` move runs **cycle detection**: if the new parent
is a descendant of the moved task, the task is moved to root instead of
creating a loop. A timeline record's task association is fixed at creation;
remote `taskId` changes to an existing record are acknowledged but ignored.

## 9. Failure handling summary

| Failure | Behavior |
|---------|----------|
| Upload fails | Watermarks not advanced; changes re-sent next cycle (idempotent under LWW). |
| Pull interrupted | Cursor persisted per blob; resume exactly where it stopped. |
| Undecryptable/corrupt blob | Skipped, sequence logged, cursor advances past it. |
| Access token expired | One transparent refresh + retry per request. |
| Refresh rejected / device revoked | Tokens cleared; fresh login next cycle. |
| Concurrent sync trigger | Rejected ("Sync already in progress"). |
| Concurrent uploads (server) | Sequence assignment serializes on the SQLite write lock; increment and insert commit atomically. |

## 10. Security properties and known limits

**Guarantees**

- Confidentiality and integrity of content against the server (AES-256-GCM;
  server stores ciphertext only).
- Origin binding: AAD ties each blob to its uploading device_id (§5.2).
- Cross-user isolation: every query is scoped by the authenticated `user_id`.

**Known limitations** (also see "Sync Hardening" in `AGENTS.md`)

- HKDF from the raw database password is fast — key strength is the password's
  strength. No PBKDF/Argon2 stretching at this layer.
- Metadata is visible to the server: usernames, device names/platforms, blob
  sizes, and upload timing.
- No replay protection beyond AAD: the server (or an attacker with server
  access) could re-serve an old blob under its original device_id; LWW
  timestamps make stale re-application harmless in practice but this is not
  cryptographically enforced.
- LWW trusts device clocks; a badly skewed clock can win conflicts it
  shouldn't.
- The change stream grows without bound (no compaction/snapshot yet).

## 11. Versioning

- `SyncPacket.version` is 1. Receivers currently parse without a version gate;
  any format change must bump this and keep decoding version-1 packets, since
  old blobs live in the stream forever.
- The HKDF info string `noo-sync-v1` pins the key derivation; changing the
  crypto scheme requires a new info string and a migration story for old blobs.
