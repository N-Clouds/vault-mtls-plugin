# Vault mTLS Plugin (N-Clouds)

A **VitoDeploy 4.x plugin** that rolls out a HashiCorp Vault Agent to a managed
server as a **Server Feature with Actions**. The agent authenticates to Vault
with AppRole and continuously issues + auto-renews short-lived PKI certificates
that nginx uses for mutual TLS (client-certificate authentication).

> **Requires Vito >= 4.x.** The v3-compatible composer-package variant lived up
> to tag `v3.x`; since Vito 4 plugins are installed from a GitHub release ZIP
> into `app/Vito/Plugins/` (see "Installing the plugin").

## What it does

Registers a server feature `vault-mtls` ("Vault mTLS") with three actions.

### Install Agent (`install-agent`)
Form fields:
- `vault_addr` (text, e.g. `https://vault.example.local:8200`)
- `ad_root_ca` (textarea) — PEM of the AD Root CA (agent `ca_cert` to trust Vault)
- `role_id` (text) — Vault AppRole role_id
- `secret_id` (password) — Vault AppRole secret_id
- `app_cns` (textarea) — newline/comma-separated service hostnames
  (e.g. `service1.example.local`)
- `hmac_kv_path` (text, optional) — Vault KV v2 path for the event-bus HMAC secret

**Re-install semantics:** if `agent.hcl` already exists on the host, every field
left empty reuses what is already there — `vault_addr`, the CN list and the HMAC
KV path are read back out of `agent.hcl`; `ad-root-ca.pem` / `role_id` /
`secret_id` are simply left untouched. Rolling out plugin/script fixes is thus
"open Install Agent, submit empty, done". `hmac_kv_path` accepts `-` to
explicitly remove the HMAC template. On a **first** install all fields except
`hmac_kv_path` are mandatory (enforced with a clear validation error).

On run it SSHes to the server (as root via `sudo`) and:
0. Installs the Vault binary if missing, via HashiCorp's official apt repository
   (rendered from `views/scripts/install-vault.blade.php`), then disables the
   bundled `vault` server service (we run only `vault agent`). Idempotent.
1. Creates `/etc/vault-agent`, `/etc/nginx/mtls`, `/run/vault-agent` and writes
   `/etc/tmpfiles.d/vault-agent.conf` so systemd recreates `/run/vault-agent`
   (tmpfs!) on every boot (rendered from `views/scripts/install-agent.blade.php`).
2. Writes `ad-root-ca.pem` (0644), `role_id` (0600), `secret_id` (0600).
3. Renders `views/scripts/agent-hcl.blade.php` and writes it to
   `/etc/vault-agent/agent.hcl`:
   - `vault { address = <vault_addr>; ca_cert = ad-root-ca.pem }`
   - `auto_auth` with AppRole method (`remove_secret_id_file_after_reading = false`)
     and a `file` sink at `/run/vault-agent/token`.
   - One `template` per CN issuing `pki_int/issue/service`
     (`common_name=<cn>`, `ttl=72h`) to `/etc/nginx/mtls/<shortname>.pem`
     (`<shortname>` = first DNS label of the CN). Its `command` chowns the cert to
     the app's OS user, runs the home-copy script (below) and reloads nginx.
   - One `template` rendering `pki_int/cert/ca_chain` to
     `/etc/nginx/mtls/ca-bundle.pem`, whose `command` also runs the home-copy
     script and reloads nginx.
3b. Renders `views/scripts/sync-home-certs.blade.php` to
   `/etc/vault-agent/sync-home-certs.sh` (0755) and runs it once.
   **Why:** an app's PHP-FPM `open_basedir` is limited to `/home/<app>/` (+ `/tmp`),
   and Guzzle stats the cert **and** CA-bundle paths in PHP before libcurl reads
   them — so an outbound `/internal` call cannot use certs under `/etc/nginx/mtls`.
   The script mirrors each app's client cert + the shared CA bundle into
   `/home/<app>/mtls/` (owner = the app user, cert `0640`, bundle `0644`). The
   agent re-runs it on **every 72 h rotation** via the template `command` hooks, so
   the home copies never go stale. The event-bus config default therefore points at
   `/home/<EVENT_BUS_APP_ID>/mtls/<EVENT_BUS_APP_ID>.pem` (CN short == OS user == app id).
4. Creates a Vito **daemon** (Worker with `site_id = null`) named `vault-agent`
   running `vault agent -config=/etc/vault-agent/agent.hcl` as `root`,
   `auto_start = true`, `auto_restart = true`. In Vito 4.x worker creation is
   **queued** (status `CREATING` until the ssh-queue job ran) — check the
   server's Daemons page for the final status.

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

**How it works (since 09/2026):** the template is derived **at runtime from the
site type**, not stored per site.

`SiteTypes/LaravelMtls` extends Vito's own `App\SiteTypes\Laravel` and overrides
`vhostTemplate()` — a method of the `SiteType` **interface**, so a contracted seam.
`Plugin::boot()` swaps only the handler of the existing `laravel` type:

```php
config(['site.types.laravel.handler' => LaravelMtls::class]);
```

Not via `RegisterSiteType`: that replaces the whole entry including label and the
seven-field create form, and a copy of those here would drift on every Vito update.
And not as a separate type `laravel-mtls`: `sites.type` would then be unresolvable
once the plugin is disabled — `Site::type()` throws, which takes down the **entire**
sites list (`SiteResource` asks every row for its type) and blocks `DeleteSite` too.
Overriding `laravel` degrades instead: without the plugin, sites keep running on
Vito's own handler, just without the mTLS vhost.

Per-site state lives in `type_data['mtls_internal']` (`cert_path`, `ca_bundle_path`);
`site.vhost_template` stays **null**. Two consequences, and both are the point:

- The template is rebuilt from Vito's **current** stock template on *every* vhost
  generation. The pre-09/2026 mechanism stored a snapshot in `site.vhost_template`,
  which froze it: a core template change only reached the site when somebody ran
  Enable again.
- Vito's PHP-settings directives are **live again**. `AbstractGenerateConfig` gates
  them on `$phpEnabled = $isPhp && $site->vhost_template === null`, so with a stored
  template they were suppressed and the plugin had to rebuild `client_max_body_size`,
  `fastcgi_read_timeout` and `PHP_VALUE` from four `type_data.php.*` keys. That
  reimplementation is **gone**: the snippet now uses Vito's own placeholders
  (`{{#php_value}}`, the globally substituted `@@VITO_PHP_VALUE@@` token,
  `{{fastcgi_read_timeout}}`), and `client_max_body_size` is simply inherited from
  server level.

Injection anchor: `}` + blank line + `{{/server_blocks}}` — verified to occur
**exactly once** in Vito 4.x's `vhost.mustache`. Any other count throws loudly
rather than writing a template that would take the site off the net at the next
nginx reload.

Constraints enforced by Enable:
- **nginx only** (Caddy is rejected with a validation error).
- **Vito-managed SSL must be off** for the site (`ssl_enabled`) — mTLS manages
  TLS itself via the agent certs; Vito's 443 blocks would collide.
- A pre-existing hand-written `site.vhost_template` is **cleared** — the mTLS
  template now comes from the site type, and a stored one would take precedence.

**Sites migrated from Vito 3.x** have per-site vhost generation disabled
(`vhost_generation_enabled = false`) — `updateVHost()` is a no-op for them, so
their live vhosts (including v3-era mTLS blocks) are untouched until you act.
For such sites Enable/Disable show a warning plus a checkbox
"Vhost-Generierung für diese Site aktivieren" (default: on). Confirming it
turns vhost generation on and regenerates the vhost fully from the template —
any manual nginx edits made outside Vito are lost.

> **Ordering requirement (critical):** run the server feature **Install Agent**
> and **wait for cert issuance** *before* enabling mTLS on a site. Enable performs
> a pre-flight SSH `test -f` on the cert file and **refuses with a validation
> error** if it is missing, because injecting `ssl_certificate` for a
> non-existent file makes `nginx reload` fail and would take the site down.

### Enable (`enable`)
Form fields (defined on the handler's `form()` so they adapt to per-site state):
- `cert_name` (text, optional) — base name of the agent-issued cert under
  `/etc/nginx/mtls`. Defaults to the **first DNS label of the site's primary
  domain** (e.g. `service1.example.local` → `service1` → `/etc/nginx/mtls/service1.pem`).
- `ca_bundle_path` (text, default `/etc/nginx/mtls/ca-bundle.pem`) — the CA bundle
  nginx uses to verify client certs (`ssl_client_certificate`).
- `enable_vhost_generation` (checkbox, default on; **only shown** when the site
  has vhost generation disabled, i.e. was migrated from Vito 3.x) — see above.

On run it:
1. Guards: webserver must be **nginx**, Vito-managed SSL must be **off**.
2. Resolves `certName` (input or first domain label) → cert path
   `/etc/nginx/mtls/{certName}.pem`.
3. **Pre-flight**: SSHes to the server (as root) and verifies the cert file
   exists; if not, throws a `ValidationException` telling you to run Install Agent
   first (injecting `ssl_certificate` for a missing file would make
   `nginx reload` fail and take the whole site down, incl. port 80).
4. Records the paths; the vhost itself is derived by `LaravelMtls::vhostTemplate()`
   on every generation — Vito's stock template with
   `views/templates/mtls-server-block.mustache` injected before the closing brace
   of the server block. The snippet adds:
   - server-level TLS + client verify (`listen 443 ssl`, `ssl_certificate*`,
     `ssl_client_certificate`, `ssl_verify_client optional`, `ssl_verify_depth 2`);
     `optional` keeps the public 443 endpoint reachable without a cert; the
     `/internal/` location does the actual enforcement. Port 80 is left intact.
   - the `/internal/` location — requests **return 403** unless a valid client
     certificate was presented;
   - a `location = /index.php` block that passes `SSL_CLIENT_VERIFY` /
     `SSL_CLIENT_S_DN` to PHP (exact match beats the stock `~ \.php$` regex;
     fastcgi_param is not inherited into a location defining its own) with
     enlarged fastcgi buffers (SSO cookie/header size) and Vito's own PHP-settings
     placeholders, which this location has to repeat because it shadows Vito's
     `~ \.php$` block and `fastcgi_param` is not inherited.
5. Stores `cert_path` + `ca_bundle_path` in `type_data['mtls_internal']`, clears
   `site.vhost_template` (a leftover snapshot from the old mechanism would win —
   `getTemplate()` asks it first), saves, and calls `updateVHost($site)` (nginx
   **reload**). Re-running Enable is idempotent; the template itself is derived
   fresh on every generation, so it can never be appended twice.

If Vito's core template layout ever changes so the injection anchor is no longer
found, Enable fails with a clear validation error instead of writing a broken
template — the plugin then needs an update.

### Disable (`disable`)
Form: only the `enable_vhost_generation` checkbox for v3-migrated sites (see
above), otherwise no form. Removes `type_data['mtls_internal']` **and** clears any
leftover `site.vhost_template` from the old mechanism, then regenerates — Vito's stock template takes over again, removing the 443/ssl +
client-verify directives (port resets to `listen 80` only) and the `/internal/`
location.

## Installing the plugin

Vito 4.x installs plugins from a **GitHub release ZIP**, not via composer:

- **Admin → Plugins → Install**: paste the repo URL
  (`https://github.com/N-Clouds/vault-mtls-plugin`). Vito downloads the latest
  **release** (a tagged release must exist — the `.github/workflows/release.yml`
  creates one per pushed tag), extracts it to
  `app/Vito/Plugins/NClouds/VaultMtlsPlugin/` and boots
  `App\Vito\Plugins\NClouds\VaultMtlsPlugin\Plugin`. Enable it on the same page.
- **Manual / development**: copy this repo to
  `app/Vito/Plugins/NClouds/VaultMtlsPlugin/` inside the Vito installation — it
  then shows up under Admin → Plugins → **Discover**.

The `composer.json` is vestigial (kept for repo-local tooling); Vito 4 autoloads
the plugin through the app's own `App\` PSR-4 mapping. If the plugin's `boot()`
throws, Vito auto-disables it and records the error under Admin → Plugins.

After enabling, open a server → **Features** tab for the "Vault mTLS" server
feature, and a Laravel site → **Features** tab for "mTLS /internal".

## Vault HA und wo der Zustand liegt

### The address must be the cluster endpoint

`agent.hcl` takes exactly **one** `address`. With an HA cluster that has to be the
load-balanced endpoint (or the `active` alias), **not a single node** — after a
leader election the agent would otherwise be talking to a standby, which answers
write paths with a 307 to the active node.

The agent config therefore carries three deliberate HA settings:

| | |
|---|---|
| `vault { retry { num_retries = 12 } }` | during a leader election the cluster is briefly not writable. Without retry the agent **exits** — certs expire, `eventbus-hmac` stops being renewed, and it only shows days later |
| `template_config { exit_on_retry_failure = false }` | a failed render is normal in HA and no reason to leave; supervisor would only restart the process and the fetched token would be lost |
| `auto_auth` `min_backoff`/`max_backoff` | if the cluster is mid-election at agent start, wait instead of giving up |

The load balancer needs a certificate signed by the **AD Root CA** with the endpoint
name in its SAN — that CA is what `ca_cert` pins.

> **Vault being down does not break signing.** `VaultFileSigningKeyResolver` reads the
> *file* the agent rendered, not Vault. Once rendered it survives any outage. What
> breaks is a host that never had an agent — see below.

### State lives in Vito, not in `agent.hcl`

`Zustand` keeps vault address, CN list and HMAC KV path in
`servers.feature_data['vault-mtls']` — the same store Vito uses for server features
(`ManagePasswordAuth`, `DetectSecurityJob`).

Until 09/2026 the written `agent.hcl` *was* the state store: `InstallAgent` and
`ManageCns` read those three values back with `grep -oP`, and one anchor was a
**comment string**:

```
grep -oP '# Event-bus HMAC signing secret from Vault KV \(\K[^)]+'
```

Reword that comment in the Blade template and `ManageCns` loses the KV path — the
HMAC template vanishes from the regenerated `agent.hcl`, the secret stops being
renewed, and nothing says so until the next rotation.

The greps remain as a **fallback** for hosts set up before this change: `Zustand::lesen()`
reads them once and writes the result into Vito, so the first `Install Agent` or
`Manage service names` migrates the host by itself. `Uninstall` removes the entry —
otherwise a later install would report a re-install and adopt the CN list of an agent
that no longer exists.

### Consistency across apps is not optional

All apps must resolve the **same** signing key. On 27.09.2026 central ran
`VaultFileSigningKeyResolver` while a freshly installed CMS ran
`ConfigSigningKeyResolver` with a secret its own installer had generated: every event
from central landed in the CMS DLQ as `DroppedMessageException('signature')`, and
nothing reported the drift. `event-bus:doctor` now checks it — it prints the active
resolver plus a fingerprint of the key the resolver actually returns, and fails when a
vault-agent file exists but the app reads its key from config.

Onboarding checklist per new host: install the agent, issue an AppRole `secret_id`,
add the app CN, switch the app to `VaultFileSigningKeyResolver`, `event-bus:doctor`
green.

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
- **No version pin for the `vault` package.** `apt-get install -y vault` takes
  whatever is current. With several hosts the agent versions drift, and so does the
  HCL semantics this plugin relies on. Pin it, or at least record the installed
  version in `Zustand`.
- **No `error_on_missing_key` on the HMAC template.** If the KV path exists but has
  no `current` key, the Go template renders **empty** and the file is truncated to
  zero bytes — the apps then report
  `event_bus.signing_secret is not configured`, which points at the wrong place
  entirely. A missing key should abort the render, not blank the file. Not changed
  yet because a bad HCL stops the agent from starting and this could not be
  validated without a Vault.
- **AD root concatenation** into the client-verify bundle is manual (see caveat).
- The daemon runs as **root**. A dedicated `vault` user must exist and be one of
  the server's known SSH users (Vito validates the worker `user` against
  `Server::getSshUsers()`), and `/run/vault-agent` + `/etc/nginx/mtls` must be
  writable by it.
- Certificate `ttl` is fixed at `72h`; adjust in `views/scripts/agent-hcl.blade.php`
  if your PKI role enforces a different max TTL.
- The token sink `/run/vault-agent/token` lives on tmpfs. The **directory** is
  recreated on boot via `/etc/tmpfiles.d/vault-agent.conf` (written by Install
  Agent). Without that entry the agent dies at startup after a reboot
  (`error creating file sink: ... no such file or directory`), supervisor stops
  retrying (FATAL after a few attempts), rotation stops, and the 72h certs
  expire ~3 days later — internal HTTPS callers then fail with
  `cURL error 60: certificate has expired`. Recovery:
  `mkdir -p /run/vault-agent && chmod 700 /run/vault-agent`, then restart the
  `vault-agent` daemon (Vito → Daemons, or `supervisorctl restart`).
