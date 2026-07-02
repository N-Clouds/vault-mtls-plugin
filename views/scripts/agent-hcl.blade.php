vault {
  address = "{{ $vaultAddr }}"
  ca_cert = "{{ $agentDir }}/ad-root-ca.pem"
}

auto_auth {
  method "approle" {
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
