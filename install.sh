#!/usr/bin/env bash
#
# Install or upgrade the Noo sync relay on a Linux server with systemd.
#
#   curl -fsSL https://github.com/lab517io/noo-relay/releases/latest/download/install.sh | sudo bash
#
# Settings are passed as environment variables, after `sudo`:
#
#   curl -fsSL https://github.com/lab517io/noo-relay/releases/latest/download/install.sh \
#     | sudo NOO_LISTEN_ADDR=0.0.0.0:8080 bash
#
#   NOO_VERSION           release to install, e.g. 1.0.0 (default: latest)
#   NOO_RELEASE_URL       GitHub-style releases base URL
#                         (default: https://github.com/lab517io/noo-relay/releases)
#   NOO_TARBALL           install from a local tarball instead of downloading
#   NOO_LISTEN_ADDR       default 127.0.0.1:8080 — put a TLS reverse proxy in front
#   NOO_TLS_CERT_FILE     serve HTTPS directly; set together with NOO_TLS_KEY_FILE
#   NOO_TLS_KEY_FILE
#   NOO_MAX_PAYLOAD_SIZE  max packet upload size in bytes (default 10 MB)
#   NOO_REGISTRATION      open | closed (default closed: create accounts in the
#                         admin dashboard)
#   NOO_USER_QUOTA_BYTES  per-account storage limit in bytes (default 0: none)
#   NOO_TRUSTED_PROXIES   proxies whose X-Forwarded-For is believed (default on
#                         a loopback install: 127.0.0.1,::1)
#
# Re-running it upgrades the binary and dashboard in place. The database and the
# secrets in /etc/noo-sync.env are never overwritten; a setting passed explicitly
# on a re-run replaces the one in the file. If the upgraded service fails its
# health check, the previous binary is put back.
#
# The layout matches the reference deployment (DEPLOYMENT.md), so a server set up
# by this script can later be driven by deploy.sh.
set -euo pipefail

RELEASE_URL="${NOO_RELEASE_URL:-https://github.com/lab517io/noo-relay/releases}"
VERSION="${NOO_VERSION:-latest}"

APP_DIR=/opt/noo-sync
DATA_DIR=/var/lib/noo-sync
ENV_FILE=/etc/noo-sync.env
UNIT=noo-sync.service
UNIT_PATH="/etc/systemd/system/${UNIT}"
SERVICE_USER=noosync

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mWARNING: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# Everything runs inside main, called on the last line: with `curl | bash`, a
# download cut short would otherwise execute a truncated script.
main() {
  preflight
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT

  fetch "$WORK"
  create_user
  local fresh=0
  [ -f "$ENV_FILE" ] || fresh=1
  write_env "$fresh"
  install_files "$WORK"
  write_unit

  if [ "$HAVE_SYSTEMD" -eq 1 ]; then
    start_and_verify
  else
    swap_in
    warn "systemd is not running; the service was installed but not started."
    echo "  Start it by hand:  sudo -u ${SERVICE_USER} env \$(grep -v '^#' ${ENV_FILE} | xargs) ${APP_DIR}/relay"
  fi
  summary "$fresh"
}

# --------------------------------------------------------------------------
preflight() {
  [ "$(id -u)" -eq 0 ] || die "run as root (pipe into 'sudo bash')"
  [ "$(uname -s)" = Linux ] || die "only Linux is supported"

  case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m) (amd64 and arm64 are built)" ;;
  esac

  for cmd in tar sha256sum; do
    command -v "$cmd" >/dev/null || die "'$cmd' is required"
  done
  if [ -z "${NOO_TARBALL:-}" ]; then
    command -v curl >/dev/null || command -v wget >/dev/null \
      || die "curl or wget is required"
  fi

  HAVE_SYSTEMD=0
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
    HAVE_SYSTEMD=1
  fi

  # Half a TLS pair would silently fall back to plaintext in the relay.
  if { [ -n "${NOO_TLS_CERT_FILE:-}" ] && [ -z "${NOO_TLS_KEY_FILE:-}" ]; } ||
     { [ -z "${NOO_TLS_CERT_FILE:-}" ] && [ -n "${NOO_TLS_KEY_FILE:-}" ]; }; then
    die "set NOO_TLS_CERT_FILE and NOO_TLS_KEY_FILE together"
  fi
}

download() { # url dest
  if command -v curl >/dev/null; then
    curl -fsSL --retry 3 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

fetch() {
  local work="$1" tarball="$1/relay.tar.gz"
  if [ -n "${NOO_TARBALL:-}" ]; then
    say "Using local tarball ${NOO_TARBALL}"
    cp "$NOO_TARBALL" "$tarball"
  else
    local url
    if [ "$VERSION" = latest ]; then
      url="${RELEASE_URL}/latest/download/noo-relay-linux-${ARCH}.tar.gz"
    else
      url="${RELEASE_URL}/download/v${VERSION#v}/noo-relay-linux-${ARCH}.tar.gz"
    fi
    say "Downloading ${url}"
    download "$url" "$tarball" || die "download failed: ${url}"
    download "${url}.sha256" "${tarball}.sha256" || die "checksum download failed: ${url}.sha256"
    # The checksum file names the release artefact; compare the hash alone.
    local want got
    want="$(cut -d' ' -f1 "${tarball}.sha256")"
    got="$(sha256sum "$tarball" | cut -d' ' -f1)"
    [ "$want" = "$got" ] || die "checksum mismatch (expected ${want}, got ${got})"
    echo "  sha256 OK"
  fi

  mkdir -p "${work}/x"
  tar -xzf "$tarball" -C "${work}/x"
  [ -x "${work}/x/relay" ] && [ -d "${work}/x/static" ] \
    || die "tarball does not contain relay and static/"
}

create_user() {
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    say "Creating system user ${SERVICE_USER}"
    useradd --system --home-dir "$DATA_DIR" --no-create-home \
      --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA_DIR"
  install -d -o root -g root -m 755 "$APP_DIR"
}

random_secret() {
  # 32 bytes, hex. /dev/urandom needs nothing installed.
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

# set_env writes KEY=VALUE, replacing an existing line for KEY.
set_env() {
  if grep -q "^${1}=" "$ENV_FILE"; then
    grep -qxF "${1}=${2}" "$ENV_FILE" && return 0
    local tmp; tmp="$(mktemp)"
    awk -v k="$1" -v v="$2" 'index($0, k "=") == 1 { print k "=" v; next } { print }' \
      "$ENV_FILE" > "$tmp"
    cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"
    echo "  ~ ${1}"
  else
    echo "${1}=${2}" >> "$ENV_FILE"
    echo "  + ${1}"
  fi
}

write_env() {
  local fresh="$1"
  if [ "$fresh" -eq 1 ]; then
    say "Writing ${ENV_FILE} with fresh secrets"
    umask 027
    cat > "$ENV_FILE" <<EOF
# Noo sync relay settings. Read by ${UNIT}; restart it after editing.
NOO_JWT_SECRET=$(random_secret)
NOO_ADMIN_TOKEN=$(random_secret)
NOO_DATABASE_URL=${DATA_DIR}/noo_sync.db
NOO_STATIC_DIR=${APP_DIR}/static
NOO_LISTEN_ADDR=${NOO_LISTEN_ADDR:-127.0.0.1:8080}
EOF
    umask 022
  else
    say "Keeping ${ENV_FILE}"
    [ -n "${NOO_LISTEN_ADDR:-}" ] && set_env NOO_LISTEN_ADDR "$NOO_LISTEN_ADDR"
  fi

  # On loopback the only peers are local reverse proxies, whose
  # X-Forwarded-For is what tells one client from another for the login rate
  # limits; without it every client would share the proxy's budget. Added
  # whenever absent, so installs from before 1.0.1 pick it up on upgrade.
  case "$(env_value NOO_LISTEN_ADDR)" in
    127.0.0.1:*|localhost:*|"[::1]":*)
      if [ -z "${NOO_TRUSTED_PROXIES:-}" ] && ! grep -q '^NOO_TRUSTED_PROXIES=' "$ENV_FILE"; then
        set_env NOO_TRUSTED_PROXIES "127.0.0.1,::1"
      fi ;;
  esac

  # Settings passed explicitly apply on every run, fresh or not.
  [ -n "${NOO_TLS_CERT_FILE:-}" ]    && set_env NOO_TLS_CERT_FILE "$NOO_TLS_CERT_FILE"
  [ -n "${NOO_TLS_KEY_FILE:-}" ]     && set_env NOO_TLS_KEY_FILE "$NOO_TLS_KEY_FILE"
  [ -n "${NOO_MAX_PAYLOAD_SIZE:-}" ] && set_env NOO_MAX_PAYLOAD_SIZE "$NOO_MAX_PAYLOAD_SIZE"
  [ -n "${NOO_REGISTRATION:-}" ]     && set_env NOO_REGISTRATION "$NOO_REGISTRATION"
  [ -n "${NOO_USER_QUOTA_BYTES:-}" ] && set_env NOO_USER_QUOTA_BYTES "$NOO_USER_QUOTA_BYTES"
  [ -n "${NOO_TRUSTED_PROXIES:-}" ]  && set_env NOO_TRUSTED_PROXIES "$NOO_TRUSTED_PROXIES"

  chown "root:${SERVICE_USER}" "$ENV_FILE"
  chmod 640 "$ENV_FILE"
}

install_files() {
  local src="$1/x"
  say "Installing binary and dashboard into ${APP_DIR}"
  install -o root -g root -m 755 "${src}/relay" "${APP_DIR}/relay.new"
  rm -rf "${APP_DIR}/static.new"
  cp -r "${src}/static" "${APP_DIR}/static.new"
  chown -R root:root "${APP_DIR}/static.new"
  chmod -R u=rwX,go=rX "${APP_DIR}/static.new"
}

# Keep in step with the unit heredoc in deploy.sh.
write_unit() {
  [ -d /etc/systemd/system ] || return 0
  cat > "$UNIT_PATH" <<UNITFILE
[Unit]
Description=Noo Sync Server (Go)
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/relay
Restart=on-failure
RestartSec=3

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
UNITFILE
}

# swap_in moves the staged files into place, keeping the outgoing binary as
# relay.prev — the same one-step rollback deploy.sh relies on.
swap_in() {
  if [ -f "${APP_DIR}/relay" ]; then mv -f "${APP_DIR}/relay" "${APP_DIR}/relay.prev"; fi
  mv "${APP_DIR}/relay.new" "${APP_DIR}/relay"
  rm -rf "${APP_DIR}/static.prev"
  if [ -d "${APP_DIR}/static" ]; then mv "${APP_DIR}/static" "${APP_DIR}/static.prev"; fi
  mv "${APP_DIR}/static.new" "${APP_DIR}/static"
}

swap_back() {
  [ -f "${APP_DIR}/relay.prev" ] || return 1
  mv -f "${APP_DIR}/relay.prev" "${APP_DIR}/relay"
  if [ -d "${APP_DIR}/static.prev" ]; then
    rm -rf "${APP_DIR}/static"; mv "${APP_DIR}/static.prev" "${APP_DIR}/static"
  fi
}

env_value() { # key
  grep "^${1}=" "$ENV_FILE" | tail -n1 | cut -d= -f2-
}

health_url() {
  local addr host port scheme=http
  addr="$(env_value NOO_LISTEN_ADDR)"; addr="${addr:-0.0.0.0:8080}"
  host="${addr%:*}"; port="${addr##*:}"
  case "$host" in ""|0.0.0.0|"[::]") host=127.0.0.1 ;; esac
  [ -n "$(env_value NOO_TLS_CERT_FILE)" ] && scheme=https
  echo "${scheme}://${host}:${port}/health"
}

healthy() {
  local url; url="$(health_url)"
  local _
  for _ in $(seq 1 20); do
    # -k: the certificate names the public host, not the loopback address.
    if command -v curl >/dev/null; then
      curl -fsk --max-time 3 "$url" >/dev/null 2>&1 && return 0
    else
      wget -q --no-check-certificate -T 3 -O /dev/null "$url" 2>/dev/null && return 0
    fi
    sleep 1
  done
  return 1
}

start_and_verify() {
  say "Starting ${UNIT}"
  systemctl daemon-reload
  systemctl stop "$UNIT" 2>/dev/null || true
  swap_in
  systemctl enable --quiet "$UNIT"
  systemctl start "$UNIT"

  if healthy; then
    echo "  health OK ($(health_url))"
    return 0
  fi

  journalctl -u "$UNIT" -n 20 --no-pager -o cat || true
  if swap_back; then
    warn "health check failed — restoring the previous version"
    systemctl restart "$UNIT"
    die "upgrade rolled back; the previous version is running again"
  fi
  die "the relay did not become healthy; see: journalctl -u ${UNIT}"
}

summary() {
  local fresh="$1"
  say "Done"
  echo "  Version:    $("${APP_DIR}/relay" -version)"
  echo "  Listening:  $(env_value NOO_LISTEN_ADDR)"
  echo "  Health:     $(health_url)"
  echo "  Dashboard:  $(health_url | sed 's|/health$|/admin/|')"
  echo "  Config:     ${ENV_FILE}"
  echo "  Database:   ${DATA_DIR}/noo_sync.db"
  echo "  Logs:       journalctl -u ${UNIT} -f"
  if [ "$(env_value NOO_REGISTRATION)" = open ]; then
    echo "  Accounts:   open registration: anyone who reaches the relay can sign up"
  else
    echo "  Accounts:   registration closed: create users in the dashboard"
    echo "              (or re-run with NOO_REGISTRATION=open)"
  fi
  if [ "$fresh" -eq 1 ]; then
    echo
    echo "  Admin token (for the dashboard; also in ${ENV_FILE}):"
    echo "    $(env_value NOO_ADMIN_TOKEN)"
  fi
  case "$(env_value NOO_LISTEN_ADDR)" in
    127.0.0.1:*|localhost:*|"[::1]":*)
      echo
      echo "  The relay listens on loopback only. Expose it through a reverse proxy"
      echo "  that terminates TLS, e.g. Caddy:  reverse_proxy $(env_value NOO_LISTEN_ADDR)"
      ;;
    *)
      if [ -z "$(env_value NOO_TLS_CERT_FILE)" ]; then
        echo
        warn "the relay is reachable without TLS; passwords and tokens travel in clear."
      fi
      ;;
  esac
}

main "$@"
