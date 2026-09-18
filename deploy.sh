#!/usr/bin/env bash
#
# Build and deploy the Go relay to noo.lab517.io, and build releases.
#
#   ./deploy.sh build      cross-compile the binary into build/, run the tests
#   ./deploy.sh deploy     build, back up the database, cut over, verify
#   ./deploy.sh rollback   restore the previous service and restart
#   ./deploy.sh status     what is running right now
#   ./deploy.sh release    build the install.sh artefacts (amd64 + arm64) into build/release/
#   ./deploy.sh github-release
#                          release, then attach it to a GitHub release v<version>
#                          of lab517io/noo-relay (run scripts/publish_public.py first)
#
# The cutover keeps the existing database, /etc/noo-sync.env secrets, nginx
# config and TLS certificates untouched. The previous unit file and binary are
# saved on the server so `rollback` is a single command.
set -euo pipefail

HOST="${NOO_DEPLOY_HOST:-root@noo.lab517.io}"
PUBLIC_URL="${NOO_PUBLIC_URL:-https://noo.lab517.io}"
REMOTE_DIR=/opt/noo-sync
REMOTE_DATA=/var/lib/noo-sync
ENV_FILE=/etc/noo-sync.env
UNIT=noo-sync.service
UNIT_PATH="/etc/systemd/system/${UNIT}"
BACKUP_DIR=/root/noo-deploy
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${REPO_ROOT}/build"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

remote() { ssh -o BatchMode=yes "$HOST" "$@"; }

# --------------------------------------------------------------------------
build() {
  say "Testing"
  ( cd "${REPO_ROOT}/go" && go test ./... )

  say "Building static linux/amd64 binary"
  mkdir -p "$BUILD_DIR"
  compile amd64 "${BUILD_DIR}/relay"
  say "Built ${BUILD_DIR}/relay ($(du -h "${BUILD_DIR}/relay" | cut -f1), $(relay_version) $(commit_id))"
}

# relay_version is the release number, read from its one definition in main.go.
relay_version() {
  sed -n 's/^const version = "\(.*\)"$/\1/p' "${REPO_ROOT}/go/cmd/relay/main.go"
}

commit_id() {
  git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unknown
}

# compile ARCH OUT builds one static linux binary, stamped with the commit.
compile() {
  # CGO_ENABLED=0 with the pure-Go SQLite driver produces a binary with no
  # libc dependency, so nothing needs installing on the server.
  ( cd "${REPO_ROOT}/go" && CGO_ENABLED=0 GOOS=linux GOARCH="$1" \
      go build -trimpath -ldflags "-s -w -X main.commit=$(commit_id)" \
      -o "$2" ./cmd/relay )
  file "$2" | grep -q "statically linked" || die "$2 is not statically linked"
}

# --------------------------------------------------------------------------
# release builds what install.sh downloads, into build/release/:
#   noo-relay-linux-<arch>.tar.gz   relay + static/, for amd64 and arm64
#   noo-relay-linux-<arch>.tar.gz.sha256
#   install.sh
# The asset names carry no version, so GitHub's releases/latest/download/<name>
# always resolves to the newest release.
release() {
  [ -z "$(git -C "$REPO_ROOT" status --porcelain)" ] \
    || die "refusing to release from a dirty tree: commit first"
  say "Testing"
  ( cd "${REPO_ROOT}/go" && go test ./... )

  local out="${BUILD_DIR}/release" arch stage name
  rm -rf "$out"; mkdir -p "$out"
  for arch in amd64 arm64; do
    say "Building linux/${arch}"
    stage="$(mktemp -d)"
    compile "$arch" "${stage}/relay"
    cp -r "${REPO_ROOT}/static" "${stage}/static"
    name="noo-relay-linux-${arch}.tar.gz"
    tar -czf "${out}/${name}" -C "$stage" --owner=0 --group=0 relay static
    ( cd "$out" && sha256sum "$name" > "${name}.sha256" )
    rm -rf "$stage"
  done
  cp "${REPO_ROOT}/install.sh" "${out}/install.sh"
  say "Release $(relay_version) ($(commit_id)) in ${out}"
  ls -lh "$out"
}

# github_release publishes build/release/ as GitHub release v<version>.
#
# The tag goes on the public snapshot (GitHub's main), not on master: master's
# history is never published. So the snapshot must already carry this code —
# checked below by comparing the published branch with master.
github_release() {
  local repo=lab517io/noo-relay tag
  tag="v$(relay_version)"
  command -v gh >/dev/null || die "gh (GitHub CLI) is required"

  git -C "$REPO_ROOT" fetch --quiet github main
  git -C "$REPO_ROOT" diff --quiet FETCH_HEAD master -- go static install.sh \
    || die "GitHub main does not match master; run scripts/publish_public.py first"
  gh release view "$tag" --repo "$repo" >/dev/null 2>&1 \
    && die "release ${tag} already exists; bump the version in go/cmd/relay/main.go"

  release
  say "Creating GitHub release ${tag}"
  gh release create "$tag" --repo "$repo" --target main \
    --title "noo-relay ${tag#v}" \
    --notes "Install or upgrade on a Linux server with systemd (amd64 or arm64):

\`\`\`bash
curl -fsSL https://github.com/${repo}/releases/latest/download/install.sh | sudo bash
\`\`\`

See README.md and DEPLOYMENT.md for settings and TLS." \
    "${BUILD_DIR}/release/"*
}

# --------------------------------------------------------------------------
deploy() {
  build

  say "Recording pre-deploy state"
  local before
  before="$(row_counts)"
  echo "  users/devices/packets = ${before//|//}"

  say "Backing up the database"
  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  remote "mkdir -p ${BACKUP_DIR} && \
    sqlite3 ${REMOTE_DATA}/noo_sync.db \".backup ${BACKUP_DIR}/noo_sync_${stamp}.db\" && \
    ls -lh ${BACKUP_DIR}/noo_sync_${stamp}.db"

  say "Uploading binary and dashboard"
  scp -q "${BUILD_DIR}/relay" "${HOST}:${REMOTE_DIR}/relay.new"
  rsync -az --delete "${REPO_ROOT}/static/" "${HOST}:${REMOTE_DIR}/static/"

  say "Cutting over"
  # Everything from the stop to the health check runs in one remote script so
  # the service is down for as little time as possible.
  local cutover_rc=0
  ssh -o BatchMode=yes "$HOST" "STAMP='${stamp}' bash -s" <<'REMOTE' || cutover_rc=$?
set -euo pipefail
REMOTE_DIR=/opt/noo-sync
ENV_FILE=/etc/noo-sync.env
UNIT_PATH=/etc/systemd/system/noo-sync.service
BACKUP_DIR=/root/noo-deploy

# Keep the outgoing unit file once, so rollback always has the original.
if [ ! -f "${BACKUP_DIR}/noo-sync.service.previous" ]; then
  cp "$UNIT_PATH" "${BACKUP_DIR}/noo-sync.service.previous"
  echo "  saved previous unit -> ${BACKUP_DIR}/noo-sync.service.previous"
fi

# The Go binary needs the listen address, TLS pair, dashboard path and trusted
# proxies. Only these are managed here; the secrets and NOO_DATABASE_URL
# already in the file are never named, so they are never touched.
#
# set_env overwrites an existing value rather than skipping it. Appending only
# when absent would make the deployment shape write-once: changing a port or a
# certificate path below would apply to a fresh server and silently do nothing
# to this one, which is the drift the unit-file heredoc exists to prevent.
set_env() {
  if grep -q "^${1}=" "$ENV_FILE"; then
    grep -qx "${1}=${2}" "$ENV_FILE" && return 0
    sed -i "s|^${1}=.*|${1}=${2}|" "$ENV_FILE"
    echo "  ~ ${1}=${2}"
  else
    echo "${1}=${2}" >> "$ENV_FILE"
    echo "  + ${1}=${2}"
  fi
}
set_env NOO_LISTEN_ADDR      127.0.0.1:8443
set_env NOO_TLS_CERT_FILE    /var/lib/noo-sync/certs/fullchain.pem
set_env NOO_TLS_KEY_FILE     /var/lib/noo-sync/certs/privkey.pem
set_env NOO_STATIC_DIR       /opt/noo-sync/static
# The listener is loopback-only, so every peer is the local reverse proxy;
# believe its X-Forwarded-For, or the login rate limit would lump all clients
# together under the proxy's address.
set_env NOO_TRUSTED_PROXIES  127.0.0.1,::1
chown root:noosync "$ENV_FILE"; chmod 640 "$ENV_FILE"

# Keep in step with write_unit in install.sh.
cat > "$UNIT_PATH" <<'UNITFILE'
[Unit]
Description=Noo Sync Server (Go)
After=network.target

[Service]
Type=simple
User=noosync
Group=noosync
WorkingDirectory=/opt/noo-sync
EnvironmentFile=/etc/noo-sync.env
ExecStart=/opt/noo-sync/relay
Restart=on-failure
RestartSec=3

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/noo-sync
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
UNITFILE

systemctl stop noo-sync
# Cold-copy the database now that no writer is attached. The -wal and -shm
# files come too: in WAL mode the main file alone is whatever was last
# checkpointed, so copying it by itself would silently drop recent commits in
# exactly the case this copy exists for — a stop that did not close cleanly.
# (SQLite deletes both on a clean last-connection close, hence the guards.)
cp -a /var/lib/noo-sync/noo_sync.db "${BACKUP_DIR}/noo_sync_${STAMP}.cold.db"
for suffix in wal shm; do
  if [ -f "/var/lib/noo-sync/noo_sync.db-${suffix}" ]; then
    cp -a "/var/lib/noo-sync/noo_sync.db-${suffix}" \
          "${BACKUP_DIR}/noo_sync_${STAMP}.cold.db-${suffix}"
  fi
done

if [ -f "${REMOTE_DIR}/relay" ]; then
  mv "${REMOTE_DIR}/relay" "${REMOTE_DIR}/relay.prev"
fi
mv "${REMOTE_DIR}/relay.new" "${REMOTE_DIR}/relay"
chown root:root "${REMOTE_DIR}/relay"; chmod 755 "${REMOTE_DIR}/relay"

systemctl daemon-reload
systemctl enable --quiet noo-sync
systemctl start noo-sync
REMOTE

  say "Verifying"
  if [ "$cutover_rc" -ne 0 ]; then
    printf '\033[31mCutover script failed (exit %s)\033[0m\n' "$cutover_rc"
  fi
  local ok=1
  for attempt in $(seq 1 20); do
    if curl -sf --max-time 5 "${PUBLIC_URL}/health" >/dev/null 2>&1; then ok=0; break; fi
    sleep 1
  done

  if [ "$ok" -ne 0 ]; then
    printf '\033[31mHealth check failed — rolling back\033[0m\n'
    remote "journalctl -u ${UNIT} -n 30 --no-pager" || true
    rollback
    die "deployment rolled back to the previous binary"
  fi

  local after
  after="$(row_counts)"

  # Only the user count is invariant across a cutover. The service is live
  # again by now, so a client can legitimately register a device or upload a
  # packet in the seconds the health check took, and a snapshot upload prunes
  # packets by design — comparing those for equality fails healthy deploys.
  # A user disappearing is the one thing no amount of traffic explains.
  local before_users after_users
  before_users="${before%%|*}"; after_users="${after%%|*}"
  [ "$after_users" -ge "$before_users" ] \
    || die "users lost across the cutover: ${before//|//} -> ${after//|//}"

  echo "  health OK (users/devices/packets ${before//|//} -> ${after//|//};"
  echo "             device and packet counts move with live traffic and compaction)"
  status
}

# row_counts prints users|devices|packets from the live database.
row_counts() {
  remote "sqlite3 ${REMOTE_DATA}/noo_sync.db \
    'SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM devices), (SELECT COUNT(*) FROM packets);'"
}

# --------------------------------------------------------------------------
# rollback swaps the previous binary back in — one deploy backwards. Every
# deploy keeps the outgoing binary as relay.prev, so this always undoes the most
# recent one. (Before 2026-08-30 this restored the uvicorn unit; the Python
# source is no longer in the repository.)
rollback() {
  say "Rolling back to the previous binary"
  remote "set -e
    [ -f ${REMOTE_DIR}/relay.prev ] || { echo 'no previous binary to roll back to'; exit 1; }
    # Keep what we rolled back from, so the rollback is itself reversible.
    if [ -f ${REMOTE_DIR}/relay ]; then mv ${REMOTE_DIR}/relay ${REMOTE_DIR}/relay.rolledback; fi
    mv ${REMOTE_DIR}/relay.prev ${REMOTE_DIR}/relay
    chown root:root ${REMOTE_DIR}/relay; chmod 755 ${REMOTE_DIR}/relay
    systemctl restart ${UNIT}
    sleep 2
    systemctl is-active ${UNIT}"
  curl -sf --max-time 10 "${PUBLIC_URL}/health" && echo "  rollback healthy" || echo "  WARNING: health check still failing"
}

# --------------------------------------------------------------------------
status() {
  say "Service status"
  remote "systemctl is-active ${UNIT}; \
    grep -E '^(Description|ExecStart)=' ${UNIT_PATH}; \
    echo; journalctl -u ${UNIT} -n 5 --no-pager -o cat"
  echo
  echo -n "  ${PUBLIC_URL}/health -> "
  curl -sf --max-time 10 "${PUBLIC_URL}/health" || echo "UNREACHABLE"
  echo
}

case "${1:-deploy}" in
  build)    build ;;
  deploy)   deploy ;;
  rollback) rollback ;;
  status)   status ;;
  release)  release ;;
  github-release) github_release ;;
  *)        die "usage: $0 [build|deploy|rollback|status|release|github-release]" ;;
esac
