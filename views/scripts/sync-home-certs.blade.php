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

  # `install -d` setzt Eigentuemer und Modus BEIM Anlegen. Ein `mkdir -p` mit
  # nachtraeglichem chmod liesse das Verzeichnis bis dahin mit der Umask der Wurzel
  # stehen (meist 0755) — in diesem Fenster koennte ein fremder App-Benutzer
  # auflisten, welche Dateien hier liegen.
  install -d -m 0750 -o "$short" "$dir" 2>/dev/null || mkdir -p "$dir" || return 0

  if [ -f "$MTLS_DIR/$short.pem" ]; then
    # Client-Zertifikat, enthaelt den privaten Schluessel. Modus BEIM Anlegen, nicht danach: Zwischen `cp` und `chmod`
    # stuende die Datei mit der Umask der Wurzel da (meist 0644). Bei einem
    # Geheimnis ist das ein Lesefenster fuer jeden lokalen Benutzer — und es
    # wiederholt sich bei JEDER Rotation.
    install -m 0640 -o "$short" "$MTLS_DIR/$short.pem" "$dir/$short.pem" 2>/dev/null || true
  fi

  if [ -f "$MTLS_DIR/ca-bundle.pem" ]; then
    # CA-Bundle, oeffentlich (0644) — hier geht es nicht um Geheimhaltung, sondern
    # um Einheitlichkeit: derselbe Aufruf wie oben, damit nicht eine Datei anders
    # entsteht als die andere.
    install -m 0644 -o "$short" "$MTLS_DIR/ca-bundle.pem" "$dir/ca-bundle.pem" 2>/dev/null || true
  fi

  # Event-bus HMAC secret (present only when the KV template is enabled). Secret →
  # owner-readable only (0640), like the client cert.
  if [ -f "$MTLS_DIR/eventbus-hmac" ]; then
    # HMAC-Geheimnis der Plattform. Modus BEIM Anlegen, nicht danach: Zwischen `cp` und `chmod`
    # stuende die Datei mit der Umask der Wurzel da (meist 0644). Bei einem
    # Geheimnis ist das ein Lesefenster fuer jeden lokalen Benutzer — und es
    # wiederholt sich bei JEDER Rotation.
    install -m 0640 -o "$short" "$MTLS_DIR/eventbus-hmac" "$dir/eventbus-hmac" 2>/dev/null || true
  fi

  # Owner-only dir so another app's user can't list this app's mtls dir.
  chown "$short" "$dir" 2>/dev/null || true
  chmod 0750 "$dir" 2>/dev/null || true
}
@foreach ($cns as $cn)
sync_app "{{ $cn['short'] }}" "{{ $cn['home'] }}"
@endforeach
