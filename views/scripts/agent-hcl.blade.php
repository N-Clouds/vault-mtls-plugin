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
  command     = "systemctl reload nginx"
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
  command     = "systemctl reload nginx"
}
