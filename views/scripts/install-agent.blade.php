#!/bin/bash
set -e

# Prepare the Vault Agent working directories.
# - {{ $agentDir }}  : agent config + AppRole credentials + trust material
# - {{ $mtlsDir }}   : rendered nginx client/server certificates
# - {{ $tokenDir }}  : auto-auth token sink (tmpfs)
sudo mkdir -p {{ $agentDir }} {{ $mtlsDir }} {{ $tokenDir }}
sudo chmod 700 {{ $agentDir }}
sudo chmod 700 {{ $tokenDir }}
# {{ $mtlsDir }} ausdruecklich auf 0750: Die Dateien darin sind je Datei geschuetzt
# (0640 aus agent.hcl), das VERZEICHNIS blieb aber auf der Umask-Vorgabe (meist 0755).
# Damit konnte jeder lokale Benutzer auflisten, welche Dienst-CNs es auf dem Host gibt.
sudo chmod 750 {{ $mtlsDir }}

# {{ $tokenDir }} lives on /run (tmpfs) and vanishes on every reboot. Without this
# tmpfiles.d entry the agent dies at startup after a reboot ("error creating file sink:
# ... no such file or directory"), supervisor gives up retrying, and cert rotation stops
# until the 72h leafs expire. systemd-tmpfiles recreates the dir on each boot.
echo "d {{ $tokenDir }} 0700 root root -" | sudo tee /etc/tmpfiles.d/vault-agent.conf > /dev/null
sudo systemd-tmpfiles --create /etc/tmpfiles.d/vault-agent.conf
