location /internal/ {
    if ($ssl_client_verify != SUCCESS) { return 403; }
    try_files $uri $uri/ /index.php?$query_string;
}
