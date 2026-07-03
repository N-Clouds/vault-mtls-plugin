@php
    $phpSocket = "unix:/var/run/php/php{$site->php_version}-fpm.sock";
    if ($site->isIsolated()) {
        $phpSocket = "unix:/run/php/php{$site->php_version}-fpm-{$site->user}.sock";
    }
@endphp
# Exact-match location wins over the stock `location ~ \.php$` regex regardless of
# order, and try_files rewrites every Laravel request to /index.php — so ALL app
# traffic passes through here, with the verified client identity attached. fastcgi_param
# lines outside a location are NOT inherited into one that defines its own (the stock
# block sets SCRIPT_FILENAME), which is why this must be a full location block.
location = /index.php {
    fastcgi_pass {{ $phpSocket }};
    fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    include fastcgi_params;
    fastcgi_hide_header X-Powered-By;
    fastcgi_param SSL_CLIENT_VERIFY $ssl_client_verify;
    fastcgi_param SSL_CLIENT_S_DN   $ssl_client_s_dn;
}
