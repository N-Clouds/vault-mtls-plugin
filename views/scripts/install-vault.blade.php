#!/bin/bash
set -e

# Install the Vault binary via HashiCorp's official apt repository, but only if
# it is not already present. Idempotent: re-running is a no-op once installed.
if ! command -v vault >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    sudo -E apt-get update -y
    sudo -E apt-get install -y gpg wget lsb-release
    wget -qO- https://apt.releases.hashicorp.com/gpg \
        | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
        | sudo tee /etc/apt/sources.list.d/hashicorp.list >/dev/null
    sudo -E apt-get update -y
    sudo -E apt-get install -y vault
fi

# We only run the Vault AGENT subcommand (via the Vito daemon), never the
# bundled Vault server. Make sure the packaged vault server service is stopped
# and disabled so it cannot bind ports or conflict with the agent.
sudo systemctl disable --now vault 2>/dev/null || true
