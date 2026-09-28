<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Actions\Worker\CreateWorker;
use App\Actions\Worker\DeleteWorker;
use App\Helpers\SSH;
use App\Models\Worker;
use App\ServerFeatures\Action;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Zustand;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class InstallAgent extends Action
{
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

        /** @var SSH $ssh */
        $ssh = $this->server->ssh();

        // Re-install = agent.hcl already on the host. Then every empty form field means
        // "keep what is already there" (mirrors ManageCns), so rolling out script/plugin
        // fixes needs no re-typing of address, CA or credentials. On a first install all
        // fields except hmac_kv_path are mandatory.
        $isReinstall = $this->hasExistingInstall($ssh);

        $vaultAddrInput = trim((string) $request->input('vault_addr'));
        $vaultAddr = $vaultAddrInput !== ''
            ? $this->normalizeVaultAddr($vaultAddrInput)
            : ($isReinstall ? $this->readVaultAddr($ssh) : $this->missing('vault_addr', 'Vault address'));

        $adRootCa = (string) $request->input('ad_root_ca');
        if (trim($adRootCa) === '' && ! $isReinstall) {
            $this->missing('ad_root_ca', 'AD Root CA');
        }

        $roleId = trim((string) $request->input('role_id'));
        if ($roleId === '' && ! $isReinstall) {
            $this->missing('role_id', 'AppRole role_id');
        }

        $secretId = trim((string) $request->input('secret_id'));
        if ($secretId === '' && ! $isReinstall) {
            $this->missing('secret_id', 'AppRole secret_id');
        }

        $cnsInput = (string) $request->input('app_cns');
        $cns = trim($cnsInput) !== ''
            ? $this->parseCns($cnsInput)
            : ($isReinstall ? $this->readCns($ssh) : []);
        if ($cns === []) {
            $this->missing('app_cns', 'Service common names');
        }

        // '-' explicitly removes the HMAC template on a re-install (empty means "keep").
        $hmacKvPath = trim((string) $request->input('hmac_kv_path'));
        if ($hmacKvPath === '-') {
            $hmacKvPath = '';
        } elseif ($hmacKvPath === '' && $isReinstall) {
            $hmacKvPath = $this->readHmacKvPath($ssh);
        }

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

        // 2. Trust material + AppRole credentials (secret files chmod 600). Files whose
        // form field was left empty on a re-install stay untouched on the host.
        // (Vito 4.x uploads SSH::write intermediates with chmod 600 and deletes them,
        // so the v3 HardensSecretWrites mitigation is no longer needed.)
        if (trim($adRootCa) !== '') {
            $ssh->write(self::AGENT_DIR.'/ad-root-ca.pem', $adRootCa, 'root');
            $ssh->exec('sudo chmod 644 '.self::AGENT_DIR.'/ad-root-ca.pem', 'vault-mtls-chmod-ca');
        }

        if ($roleId !== '') {
            $ssh->write(self::AGENT_DIR.'/role_id', $roleId."\n", 'root');
            $ssh->exec('sudo chmod 600 '.self::AGENT_DIR.'/role_id', 'vault-mtls-chmod-roleid');
        }

        if ($secretId !== '') {
            $ssh->write(self::AGENT_DIR.'/secret_id', $secretId."\n", 'root');
            $ssh->exec('sudo chmod 600 '.self::AGENT_DIR.'/secret_id', 'vault-mtls-chmod-secretid');
        }

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

        // 4. (Re)create the vault-agent daemon (Worker with site_id = null). Deletion is
        // synchronous (supervisor program removed in the Worker deleting event); creation
        // is queued by Vito 4.x on the ssh queue, so the daemon appears as CREATING first.
        $existing = $this->existingDaemon();
        if ($existing) {
            app(DeleteWorker::class)->delete($existing);
        }

        /*
         | Den Zustand in Vito festhalten, nicht in agent.hcl.
         |
         | Bis 09/2026 war die geschriebene Datei der einzige Speicher, und
         | ManageCns las sie per grep zurueck — einer der Anker war ein
         | Kommentartext. Siehe Zustand.
         */
        Zustand::schreiben($this->server, [
            'vault_addr'   => $vaultAddr,
            'cns'          => array_column($cns, 'cn'),
            'hmac_kv_path' => $hmacKvPath,
        ]);

        app(CreateWorker::class)->create($this->server, [
            'name' => self::DAEMON_NAME,
            'command' => 'vault agent -config='.self::AGENT_DIR.'/agent.hcl',
            'user' => self::DAEMON_USER,
            'auto_start' => true,
            'auto_restart' => true,
            'numprocs' => 1,
        ]);

        $request->session()->flash('success', 'Vault Agent installed — daemon (re)creation queued, check Daemons for status.');
    }

    private function existingDaemon(): ?Worker
    {
        return $this->server->workers()
            ->whereNull('site_id')
            ->where('name', self::DAEMON_NAME)
            ->first();
    }

    private function hasExistingInstall(SSH $ssh): bool
    {
        $out = $ssh->exec(
            'sudo test -f '.self::AGENT_DIR.'/agent.hcl && echo present || echo absent',
            'vault-mtls-check-install'
        );

        return str_contains($out, 'present');
    }

    /**
     * Read the Vault address back out of the existing agent.hcl (same pattern as ManageCns).
     */
    private function readVaultAddr(SSH $ssh): string
    {
        return Zustand::lesen($this->server)['vault_addr'];
    }

    /**
     * Recover the CN list from the existing agent.hcl template blocks
     * (`... "common_name=<cn>" "ttl=..." ...`).
     *
     * @return array<int, array{cn: string, short: string, home: string}>
     */
    /**
     * Die CN-Liste dieses Servers, in der Form, die die Vorlagen brauchen.
     *
     * Der Zustand liegt in Vito ({@see Zustand}); `parseCns()` macht daraus wieder
     * `cn`/`short`/`home` und saeubert das Kuerzel, bevor es in Shell-Befehle und
     * Dateipfade geht.
     *
     * @return array<int, array{cn: string, short: string, home: string}>
     */
    private function readCns(SSH $ssh): array
    {
        return $this->parseCns(implode(' ', Zustand::lesen($this->server)['cns']));
    }

    /**
     * Preserve the event-bus HMAC KV path by reading it back from the comment anchor
     * in the existing agent.hcl (same pattern as ManageCns). Empty when not configured.
     */
    private function readHmacKvPath(SSH $ssh): string
    {
        return Zustand::lesen($this->server)['hmac_kv_path'];
    }

    private function missing(string $field, string $label): never
    {
        throw ValidationException::withMessages([
            $field => $label.' fehlt — beim Erst-Install sind alle Felder Pflicht; leer lassen (Wert vom Host wiederverwenden) geht erst beim Re-Install.',
        ]);
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
        // All fields are nullable at the form level: on a RE-install an empty field means
        // "reuse the value already on the host" (resolved in handle()); handle() enforces
        // presence on a FIRST install via missing(). The format rules still apply whenever
        // a value IS provided.
        Validator::make($request->all(), [
            // Rendered into agent.hcl `address = "..."` and grep'd back later — restrict to a
            // URL shape so no quotes/newlines/shell chars can be injected (audit M7).
            'vault_addr' => ['nullable', 'string', 'starts_with:https://,http://', 'regex:/^https?:\/\/[A-Za-z0-9.\-]+(:\d+)?\/?$/'],
            'ad_root_ca' => ['nullable', 'string'],
            'role_id'    => ['nullable', 'string'],
            'secret_id'  => ['nullable', 'string'],
            // CN list is interpolated into a shell command the vault-agent runs AS ROOT on every
            // rotation (agent.hcl `command`) and into file paths. Restrict to hostname characters
            // so no shell metacharacters (; $ () backtick |) or path separators (/) survive —
            // closes the stored root command-injection + path traversal (audit H1).
            'app_cns'      => ['nullable', 'string', 'regex:/^[A-Za-z0-9.\-,\s]+$/'],
            // Interpolated into the agent template `{{ with secret "..." }}` — KV path chars
            // only (M7). '-' is the explicit-remove sentinel handled in handle().
            'hmac_kv_path' => ['nullable', 'string', 'regex:/^[A-Za-z0-9._\/-]+$/'],
        ])->validate();
    }
}
