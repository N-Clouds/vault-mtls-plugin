# Vault mTLS Plugin (N-Clouds)

A **standalone VitoDeploy plugin** (composer package `n-clouds/vault-mtls-plugin`)
that rolls out a HashiCorp Vault Agent to a managed server as a **Server Feature
with Actions**. The agent authenticates to Vault with AppRole and continuously
issues + auto-renews short-lived PKI certificates that nginx uses for mutual TLS
(client-certificate authentication).

## What it does

Registers a server feature `vault-mtls` ("Vault mTLS") with three actions.

### Install Agent (`install-agent`)
Form fields:
- `vault_addr` (text, default `https://vault.example.local`)
- `ad_root_ca` (textarea) — PEM of the AD Root CA (agent `ca_cert` to trust Vault)
- `role_id` (text) — Vault AppRole role_id
- `secret_id` (password) — Vault AppRole secret_id
- `app_cns` (textarea) — newline/comma-separated service hostnames
  (e.g. `service1.example.local`)

On run it SSHes to the server (as root via `sudo`) and:
0. Installs the Vault binary if missing, via HashiCorp's official apt repository
   (rendered from `views/scripts/install-vault.blade.php`), then disables the
   bundled `vault` server service (we run only `vault agent`). Idempotent.
1. Creates `/etc/vault-agent`, `/etc/nginx/mtls`, `/run/vault-agent`
   (rendered from `views/scripts/install-agent.blade.php`).
2. Writes `ad-root-ca.pem` (0644), `role_id` (0600), `secret_id` (0600).
3. Renders `views/scripts/agent-hcl.blade.php` and writes it to
   `/etc/vault-agent/agent.hcl`:
   - `vault { address = <vault_addr>; ca_cert = ad-root-ca.pem }`
   - `auto_auth` with AppRole method (`remove_secret_id_file_after_reading = false`)
     and a `file` sink at `/run/vault-agent/token`.
   - One `template` per CN issuing `pki_int/issue/service`
     (`common_name=<cn>`, `ttl=72h`) to `/etc/nginx/mtls/<shortname>.pem`
     (`<shortname>` = first DNS label of the CN), with `command = "systemctl reload nginx"`.
   - One `template` rendering `pki_int/cert/ca_chain` to
     `/etc/nginx/mtls/ca-bundle.pem`.
4. Creates a Vito **daemon** (Worker with `site_id = null`) named `vault-agent`
   running `vault agent -config=/etc/vault-agent/agent.hcl` as `root`,
   `auto_start = true`, `auto_restart = true`.

Re-running Install is idempotent: an existing `vault-agent` daemon is deleted and
recreated with the fresh config.

### Rotate secret_id (`rotate-secret-id`)
Form: `secret_id` (password). Overwrites `/etc/vault-agent/secret_id` (0600) and
restarts the `vault-agent` daemon.

### Uninstall (`uninstall`)
No form. Stops + deletes the `vault-agent` daemon (removing its supervisor
program) and `rm -rf /etc/vault-agent`. **`/etc/nginx/mtls` is left in place**
because nginx vhosts may still reference the issued certificates.

## Per-site feature: mTLS /internal

In addition to the server feature, the plugin registers a **Site Feature**
`mtls-internal` ("mTLS /internal") for the **`laravel`** site type (mirroring
Vito's core Modern Deployment registration). It appears under a site →
**Features** tab with two actions, **Enable** and **Disable**.

It injects nginx client-certificate verification into the site's vhost so that
`/internal/*` requires a valid client certificate, while public traffic on
**port 80 (via the Plesk reverse proxy) keeps working**. TLS + mTLS point at the
**agent-managed cert files** under `/etc/nginx/mtls` — it does **not** use Vito's
SSL model.

> **Ordering requirement (critical):** run the server feature **Install Agent**
> and **wait for cert issuance** *before* enabling mTLS on a site. Enable performs
> a pre-flight SSH `test -f` on the cert file and **refuses with a validation
> error** if it is missing, because injecting `ssl_certificate` for a
> non-existent file makes `nginx reload` fail and would take the site down.

### Enable (`enable`)
Form fields:
- `cert_name` (text, optional) — base name of the agent-issued cert under
  `/etc/nginx/mtls`. Defaults to the **first DNS label of the site's primary
  domain** (e.g. `service1.example.local` → `service1` → `/etc/nginx/mtls/service1.pem`).
- `ca_bundle_path` (text, default `/etc/nginx/mtls/ca-bundle.pem`) — the CA bundle
  nginx uses to verify client certs (`ssl_client_certificate`).

On run it:
1. Resolves `certName` (input or first domain label) → cert path
   `/etc/nginx/mtls/{certName}.pem`.
2. **Pre-flight**: SSHes to the server (as root) and verifies the cert file
   exists; if not, throws a `ValidationException` telling you to run Install Agent
   first.
3. Updates the vhost via `webserver()->updateVHost(...)`. To stay **idempotent**
   (Enable is always available and safe to re-run), it first **regenerates** the
   `port` and `core` blocks to stock, then **appends**:
   - to the **`port`** block (server-level TLS + client verify):
     ```
     listen 443 ssl;
     listen [::]:443 ssl;
     ssl_certificate /etc/nginx/mtls/{certName}.pem;
     ssl_certificate_key /etc/nginx/mtls/{certName}.pem;
     ssl_client_certificate {caBundlePath};
     ssl_verify_client optional;
     ssl_verify_depth 2;
     ```
     `optional` keeps the public 443 endpoint reachable without a cert; the
     `/internal/` location does the actual enforcement. Port 80 is left intact.
   - to the **`core`** block (inside the `server { }` block), an internal-only
     location:
     ```
     location /internal/ {
         if ($ssl_client_verify != SUCCESS) { return 403; }
         try_files $uri $uri/ /index.php?$query_string;
     }
     ```
     Requests to `/internal/*` **return 403** unless a valid client certificate
     was presented.

   The injected snippets are rendered from
   `views/scripts/vhost-mtls-port.blade.php` and
   `views/scripts/vhost-mtls-location.blade.php`.
4. `updateVHost` restarts nginx (its default) so the change takes effect.

### Disable (`disable`)
No form. Reverts cleanly by calling
`updateVHost(regenerate: ['port', 'core'])`, which rebuilds exactly the blocks
Enable touched from Vito's stock templates — removing the 443/ssl + client-verify
directives (port resets to `listen 80` only) and the `/internal/` location.

## Installing the plugin

This is a **standalone composer package**, not files inside the Vito app. Install
it the same way as other N-Clouds Vito plugins (e.g. `n-clouds/sftp-storage-plugin`):

- via **Vito's plugin installer** (paste `n-clouds/vault-mtls-plugin`), or
- with **composer** into the Vito installation, then run plugin discovery and
  enable "Vault mTLS" in Settings → Plugins.

The package autoloads under the PSR-4 namespace
`App\Vito\Plugins\NClouds\VaultMtlsPlugin\` and is discovered as
`App\Vito\Plugins\NClouds\VaultMtlsPlugin\Plugin`. After enabling, open a server →
**Features** tab → the "Vault mTLS" feature and its actions appear there.

## Prerequisites

- **Debian/Ubuntu (apt-based) host.** Install Agent installs the Vault binary for
  you via HashiCorp's official apt repository (`views/scripts/install-vault.blade.php`)
  — only if `vault` is not already on `$PATH` — and disables the bundled `vault`
  server service (we run only the `vault agent` subcommand). The apt package places
  the binary at `/usr/bin/vault`. For non-apt distros the `install-vault` blade
  needs adjusting (e.g. a zypper/dnf/manual-download variant).
- A configured **Vault AppRole** granting access to the `pki_int` mount; supply
  its `role_id` / `secret_id`.
- Vault PKI mount `pki_int` with a role named `service` allowing the requested
  common names and a 72h TTL.
- nginx installed and configured to consume the rendered certs from
  `/etc/nginx/mtls/` (this plugin does not write nginx vhosts).
- The Vito SSH user must have passwordless `sudo` (Vito's standard assumption).

## AD root / ca-bundle caveat

The `ca-bundle.pem` template renders **only the Vault intermediate chain**
(`pki_int/cert/ca_chain`). If nginx must also verify client certificates issued
by the **AD Root CA**, concatenate the AD root (already on disk at
`/etc/vault-agent/ad-root-ca.pem`) into the client-verify bundle yourself, e.g.:

```
cat /etc/nginx/mtls/ca-bundle.pem /etc/vault-agent/ad-root-ca.pem \
  > /etc/nginx/mtls/client-ca-bundle.pem
```

Doing this in-agent is intentionally left out to keep the template simple; wire it
into your nginx provisioning or a post-render hook if required.

## Assumptions & TODOs

- **apt-based OS assumption**: `install-vault.blade.php` uses the HashiCorp apt
  repo. Non-apt distros need a different install-vault script (see Prerequisites).
- **AD root concatenation** into the client-verify bundle is manual (see caveat).
- The daemon runs as **root**. A dedicated `vault` user must exist and be one of
  the server's known SSH users (Vito validates the worker `user` against
  `Server::getSshUsers()`), and `/run/vault-agent` + `/etc/nginx/mtls` must be
  writable by it.
- Certificate `ttl` is fixed at `72h`; adjust in `views/scripts/agent-hcl.blade.php`
  if your PKI role enforces a different max TTL.
- The token sink `/run/vault-agent/token` lives on tmpfs and is recreated on boot;
  the daemon (`auto_restart = true`) re-auths automatically.
