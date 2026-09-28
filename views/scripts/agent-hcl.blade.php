# HA-Cluster: `address` MUSS der Cluster-Endpunkt sein (Lastverteiler bzw. der
# `active`-Name), nicht ein einzelner Knoten. Zeigt sie auf einen Knoten, redet der
# Agent nach einer Leader-Wahl mit einem Standby — der antwortet auf Schreibpfade mit
# 307 auf den aktiven Knoten, und ohne Weiterverfolgung bleibt das Rendern stehen.
#
# `retry` ausdruecklich gesetzt statt auf die Vorgabe zu vertrauen: Waehrend einer
# Leader-Wahl ist der Cluster kurz nicht schreibfaehig. Ohne Wiederholung endet der
# Agent, die Zertifikate laufen aus und `eventbus-hmac` wird nicht mehr erneuert —
# und beides faellt erst Tage spaeter auf.
vault {
  address = "{{ $vaultAddr }}"
  ca_cert = "{{ $agentDir }}/ad-root-ca.pem"

  retry {
    num_retries = 12
  }
}

# Nicht beenden, wenn das Rendern einer Vorlage scheitert. Im HA-Betrieb ist ein
# Fehlschlag der Normalfall (Leader-Wahl, kurzer Ausfall eines Knotens) und kein Grund,
# den Dienst zu verlassen — Supervisor wuerde ihn ohnehin nur neu starten, und dabei
# ginge der bereits geholte Token verloren.
template_config {
  exit_on_retry_failure = false
}

auto_auth {
  method "approle" {
    # Anmeldung ebenfalls mit Rueckhalt: Ist der Cluster beim Start gerade in der
    # Wahl, soll der Agent warten statt aufzugeben.
    min_backoff = "1s"
    max_backoff = "5m"

    config = {
      role_id_file_path                   = "{{ $agentDir }}/role_id"
      secret_id_file_path                 = "{{ $agentDir }}/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "{{ $tokenDir }}/token"
    }
  }
}
@foreach ($cns as $cn)

# Certificate for {{ $cn['cn'] }}
template {
  contents = <<EOT
{!! $ldelim !!} with secret "pki_int/issue/service" "common_name={{ $cn['cn'] }}" "ttl=72h" {!! $rdelim !!}
{!! $ldelim !!} .Data.certificate {!! $rdelim !!}
{!! $ldelim !!} .Data.issuing_ca {!! $rdelim !!}
{!! $ldelim !!} .Data.private_key {!! $rdelim !!}
{!! $ldelim !!} end {!! $rdelim !!}
EOT
  destination = "{{ $mtlsDir }}/{{ $cn['short'] }}.pem"
  perms       = "0640"
  # Owner = the app's OS user (= CN short label), so that app's PHP process can read its own
  # client cert (0640: owner+root only, never world-readable). chown is best-effort: if no such
  # user exists the file stays root-owned (fine — it's then only a server cert, read by nginx=root).
  # sync-home-certs.sh then copies it into the app HOME (inside its PHP open_basedir); see script.
  command     = "chown {{ $cn['short'] }} {{ $mtlsDir }}/{{ $cn['short'] }}.pem 2>/dev/null || true; {{ $agentDir }}/sync-home-certs.sh 2>/dev/null || true; systemctl reload nginx"
}
@endforeach

# Vault intermediate CA chain bundle (see README re: appending the AD root).
template {
  contents = <<EOT
{!! $ldelim !!} with secret "pki_int/cert/ca_chain" {!! $rdelim !!}
{!! $ldelim !!} .Data.certificate {!! $rdelim !!}
{!! $ldelim !!} end {!! $rdelim !!}
EOT
  destination = "{{ $mtlsDir }}/ca-bundle.pem"
  # Re-copy the CA bundle into every app HOME on rotation, then reload nginx.
  command     = "{{ $agentDir }}/sync-home-certs.sh 2>/dev/null || true; systemctl reload nginx"
}
@if(!empty($hmacKvPath))

# Event-bus HMAC signing secret from Vault KV ({{ $hmacKvPath }}).
# Line 1 = current, line 2 = previous (optional, for rotation overlap). Read at runtime
# by the app's VaultFileSigningKeyResolver. Requires the agent's AppRole policy to allow
# read on this KV path. sync-home-certs.sh mirrors it into each app HOME (open_basedir).
template {
  contents = <<EOT
{!! $ldelim !!} with secret "{{ $hmacKvPath }}" {!! $rdelim !!}{!! $ldelim !!} .Data.data.current {!! $rdelim !!}
{!! $ldelim !!} if .Data.data.previous {!! $rdelim !!}{!! $ldelim !!} .Data.data.previous {!! $rdelim !!}
{!! $ldelim !!} end {!! $rdelim !!}{!! $ldelim !!} end {!! $rdelim !!}
EOT
  destination = "{{ $mtlsDir }}/eventbus-hmac"
  perms       = "0640"
  command     = "{{ $agentDir }}/sync-home-certs.sh 2>/dev/null || true"
}
@endif
