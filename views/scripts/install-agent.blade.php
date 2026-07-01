#!/bin/bash
set -e

# Prepare the Vault Agent working directories.
# - {{ $agentDir }}  : agent config + AppRole credentials + trust material
# - {{ $mtlsDir }}   : rendered nginx client/server certificates
# - {{ $tokenDir }}  : auto-auth token sink (tmpfs)
sudo mkdir -p {{ $agentDir }} {{ $mtlsDir }} {{ $tokenDir }}
sudo chmod 700 {{ $agentDir }}
sudo chmod 700 {{ $tokenDir }}
