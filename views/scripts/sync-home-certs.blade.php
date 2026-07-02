#!/usr/bin/env bash
# Rendered by the vault-mtls plugin (InstallAgent) to {{ $agentDir }}/sync-home-certs.sh.
#
# WHY: PHP/Guzzle stat the client cert AND the CA bundle themselves (Guzzle CurlFactory
# calls file_exists) before libcurl reads them. The nginx cert dir ({{ $mtlsDir }}) sits
# OUTSIDE each site's PHP open_basedir (/home/<app>/), so an /internal call from that app
# would crash on the stat. This script copies each app's own client cert + the shared CA
# bundle into that app's HOME (/home/<app>/mtls/), which IS inside its open_basedir.
#
# The vault-agent runs it (as root) on every cert rotation via the agent.hcl `command`
# hooks, so the home copies never go stale. Best-effort per app: a missing OS user or home
# is skipped, never fatal (the agent must keep running for the other apps).
set -u

MTLS_DIR="{{ $mtlsDir }}"

sync_app() {
  local short="$1" home="$2"
  local dir="$home/mtls"

  id "$short" >/dev/null 2>&1 || return 0   # no such OS user → skip
  [ -d "$home" ] || return 0

  mkdir -p "$dir" || return 0

  if [ -f "$MTLS_DIR/$short.pem" ]; then
    cp -f "$MTLS_DIR/$short.pem" "$dir/$short.pem"
    chown "$short" "$dir/$short.pem" 2>/dev/null || true
    chmod 0640 "$dir/$short.pem" 2>/dev/null || true
  fi

  if [ -f "$MTLS_DIR/ca-bundle.pem" ]; then
    cp -f "$MTLS_DIR/ca-bundle.pem" "$dir/ca-bundle.pem"
    chown "$short" "$dir/ca-bundle.pem" 2>/dev/null || true
    chmod 0644 "$dir/ca-bundle.pem" 2>/dev/null || true
  fi

  # Owner-only dir so another app's user can't list this app's mtls dir.
  chown "$short" "$dir" 2>/dev/null || true
  chmod 0750 "$dir" 2>/dev/null || true
}
@foreach ($cns as $cn)
sync_app "{{ $cn['short'] }}" "{{ $cn['home'] }}"
@endforeach
