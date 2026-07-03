<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Actions\Worker\CreateWorker;
use App\Helpers\SSH;
use App\Models\Worker;
use App\ServerFeatures\Action;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class InstallAgent extends Action
{
    use HardensSecretWrites;

    private const VIEW_NAMESPACE = 'vault-mtls';

    private const AGENT_DIR = '/etc/vault-agent';

    private const MTLS_DIR = '/etc/nginx/mtls';

    private const TOKEN_DIR = '/run/vault-agent';

    private const DAEMON_NAME = 'vault-agent';

    private const DAEMON_USER = 'root';

    public function name(): string
    {
        return 'Install Agent';
    }

    public function active(): bool
    {
        // Always available: allows first install as well as re-running to update config.
        return true;
    }

    public function handle(Request $request): void
    {
        $this->validate($request);

        $vaultAddr = $this->normalizeVaultAddr(trim((string) $request->input('vault_addr')));
        $adRootCa = (string) $request->input('ad_root_ca');
        $roleId = trim((string) $request->input('role_id'));
        $secretId = trim((string) $request->input('secret_id'));
        $cns = $this->parseCns((string) $request->input('app_cns'));
        $hmacKvPath = trim((string) $request->input('hmac_kv_path'));

        /** @var SSH $ssh */
        $ssh = $this->server->ssh();

        // 0. Ensure the Vault binary is installed (HashiCorp apt repo). Idempotent.
        $ssh->exec(
            $this->view('scripts.install-vault', [])->render(),
            'vault-mtls-install-binary'
        );

        // 1. Directories (rendered shell script).
        $ssh->exec(
            $this->view('scripts.install-agent', [
                'agentDir' => self::AGENT_DIR,
                'mtlsDir' => self::MTLS_DIR,
                'tokenDir' => self::TOKEN_DIR,
            ]),
            'vault-mtls-prepare'
        );

        // 2. Trust material + AppRole credentials (secret files chmod 600).
        $ssh->write(self::AGENT_DIR.'/ad-root-ca.pem', $adRootCa, 'root');
        $ssh->exec('sudo chmod 644 '.self::AGENT_DIR.'/ad-root-ca.pem', 'vault-mtls-chmod-ca');

        $ssh->write(self::AGENT_DIR.'/role_id', $roleId."\n", 'root');
        $ssh->exec('sudo chmod 600 '.self::AGENT_DIR.'/role_id', 'vault-mtls-chmod-roleid');

        $ssh->write(self::AGENT_DIR.'/secret_id', $secretId."\n", 'root');
        $ssh->exec('sudo chmod 600 '.self::AGENT_DIR.'/secret_id', 'vault-mtls-chmod-secretid');

        // H2 mitigation: strip world-readability from the /tmp intermediates Vito left behind
        // for the role_id/secret_id writes above (Vito core leaks them at 0644, see the trait).
        $this->neutralizeSecretTemps($ssh);

        // 3. Agent HCL config (rendered Blade view).
        $hcl = $this->view('scripts.agent-hcl', [
            'vaultAddr' => $vaultAddr,
            'agentDir' => self::AGENT_DIR,
            'mtlsDir' => self::MTLS_DIR,
            'tokenDir' => self::TOKEN_DIR,
            'ldelim' => '{{',
            'rdelim' => '}}',
            'cns' => $cns,
            'hmacKvPath' => $hmacKvPath,
        ])->render();
        $ssh->write(self::AGENT_DIR.'/agent.hcl', $hcl, 'root');
        $ssh->exec('sudo chmod 644 '.self::AGENT_DIR.'/agent.hcl', 'vault-mtls-chmod-config');

        // 3b. Home-copy script — the agent runs it on every rotation (agent.hcl `command`)
        // to mirror each app's client cert + the CA bundle into /home/<app>/mtls/, inside
        // that app's PHP open_basedir (Guzzle stats the paths, so /etc/nginx/mtls is off-limits).
        $syncScript = $this->view('scripts.sync-home-certs', [
            'mtlsDir' => self::MTLS_DIR,
            'agentDir' => self::AGENT_DIR,
            'cns' => $cns,
        ])->render();
        $ssh->write(self::AGENT_DIR.'/sync-home-certs.sh', $syncScript, 'root');
        $ssh->exec('sudo chmod 755 '.self::AGENT_DIR.'/sync-home-certs.sh', 'vault-mtls-chmod-sync');
        // Run once now so existing certs are mirrored immediately (best-effort; the agent
        // re-runs it on the next render anyway).
        $ssh->exec('sudo '.self::AGENT_DIR.'/sync-home-certs.sh || true', 'vault-mtls-sync-home');

        // 4. (Re)create the vault-agent daemon (Worker with site_id = null).
        $existing = $this->existingDaemon();
        if ($existing) {
            // Idempotent re-install: remove the old daemon before recreating with fresh config.
            $existing->delete();
        }

        app(CreateWorker::class)->create($this->server, [
            'name' => self::DAEMON_NAME,
            'command' => 'vault agent -config='.self::AGENT_DIR.'/agent.hcl',
            'user' => self::DAEMON_USER,
            'auto_start' => true,
            'auto_restart' => true,
            'numprocs' => 1,
        ]);

        $request->session()->flash('success', 'Vault Agent installed and daemon (re)created.');
    }

    private function existingDaemon(): ?Worker
    {
        return $this->server->workers()
            ->whereNull('site_id')
            ->where('name', self::DAEMON_NAME)
            ->first();
    }

    /**
     * @return array<int, array{cn: string, short: string, home: string}>
     */
    private function parseCns(string $raw): array
    {
        $parts = preg_split('/[\s,]+/', trim($raw)) ?: [];
        $cns = [];
        foreach ($parts as $part) {
            $cn = trim($part);
            if ($cn === '') {
                continue;
            }
            $short = explode('.', $cn)[0];
            // Defense-in-depth: strip anything that isn't a hostname label char before this value
            // reaches a shell command / file path, even if validate() were bypassed (audit H1).
            $short = preg_replace('/[^A-Za-z0-9-]/', '', $short);
            $short = $short !== '' ? $short : 'service';
            $cns[] = [
                'cn' => $cn,
                'short' => $short,
                // Home dir of the app's OS user (Vito convention: /home/<user>, and the CN
                // short label == the site user == the app id). This is where the client cert
                // is mirrored so the app's PHP open_basedir can read it.
                'home' => '/home/'.$short,
            ];
        }

        return $cns;
    }

    /**
     * Ensure the Vault address carries an explicit port. Vault's API listener defaults to 8200;
     * an operator who enters just "https://vault.example.local" (no port) would otherwise have the
     * agent dial 443, where nothing listens — the SYN is dropped by the host firewall and auth
     * fails with "i/o timeout", so no token and no rendered secrets. If a port is already present
     * (e.g. :443 for a future nginx TLS proxy) it is respected untouched.
     */
    private function normalizeVaultAddr(string $addr): string
    {
        $parts = parse_url($addr);

        // Leave malformed input alone — validate() rejects anything without https://,http://.
        if ($parts === false || ! isset($parts['host']) || isset($parts['port'])) {
            return $addr;
        }

        $scheme = $parts['scheme'] ?? 'https';
        $suffix = substr($addr, strpos($addr, $parts['host']) + strlen($parts['host']));

        return $scheme.'://'.$parts['host'].':8200'.$suffix;
    }

    /**
     * Render a Blade view, ensuring the plugin view namespace is registered.
     *
     * @param  array<string, mixed>  $data
     */
    private function view(string $template, array $data): View
    {
        $finder = app('view')->getFinder();

        if (! isset($finder->getHints()[self::VIEW_NAMESPACE])) {
            app('view')->addNamespace(self::VIEW_NAMESPACE, __DIR__.'/../views');
        }

        return view(self::VIEW_NAMESPACE.'::'.$template, $data);
    }

    private function validate(Request $request): void
    {
        Validator::make($request->all(), [
            // Rendered into agent.hcl `address = "..."` and grep'd back later — restrict to a
            // URL shape so no quotes/newlines/shell chars can be injected (audit M7).
            'vault_addr' => ['required', 'string', 'starts_with:https://,http://', 'regex:/^https?:\/\/[A-Za-z0-9.\-]+(:\d+)?\/?$/'],
            'ad_root_ca' => ['required', 'string'],
            'role_id'    => ['required', 'string'],
            'secret_id'  => ['required', 'string'],
            // CN list is interpolated into a shell command the vault-agent runs AS ROOT on every
            // rotation (agent.hcl `command`) and into file paths. Restrict to hostname characters
            // so no shell metacharacters (; $ () backtick |) or path separators (/) survive —
            // closes the stored root command-injection + path traversal (audit H1).
            'app_cns'      => ['required', 'string', 'regex:/^[A-Za-z0-9.\-,\s]+$/'],
            // Interpolated into the agent template `{{ with secret "..." }}` — KV path chars only (M7).
            'hmac_kv_path' => ['nullable', 'string', 'regex:/^[A-Za-z0-9._\/-]+$/'],
        ])->validate();
    }
}
