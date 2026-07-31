#!/bin/bash
set -e

# Prepare the Vault Agent working directories.
# - {{ $agentDir }}  : agent config + AppRole credentials + trust material
# - {{ $mtlsDir }}   : rendered nginx client/server certificates
# - {{ $tokenDir }}  : auto-auth token sink (tmpfs)
sudo mkdir -p {{ $agentDir }} {{ $mtlsDir }} {{ $tokenDir }}
sudo chmod 700 {{ $agentDir }}
sudo chmod 700 {{ $tokenDir }}

# {{ $tokenDir }} lives on /run (tmpfs) and vanishes on every reboot. Without this
# tmpfiles.d entry the agent dies at startup after a reboot ("error creating file sink:
# ... no such file or directory"), supervisor gives up retrying, and cert rotation stops
# until the 72h leafs expire. systemd-tmpfiles recreates the dir on each boot.
echo "d {{ $tokenDir }} 0700 root root -" | sudo tee /etc/tmpfiles.d/vault-agent.conf > /dev/null
sudo systemd-tmpfiles --create /etc/tmpfiles.d/vault-agent.conf
