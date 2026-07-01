listen 443 ssl;
listen [::]:443 ssl;
ssl_certificate {{ $certPath }};
ssl_certificate_key {{ $certPath }};
ssl_client_certificate {{ $caBundlePath }};
ssl_verify_client optional;
ssl_verify_depth 2;
