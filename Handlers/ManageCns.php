<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Actions\Worker\ManageWorker;
use App\Helpers\SSH;
use App\Models\Worker;
use App\ServerFeatures\Action;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

/**
 * Update ONLY the list of service common names, reusing the Vault address, AD root CA and AppRole
 * credentials that Install Agent already wrote to the host. Re-renders agent.hcl and restarts the
 * vault-agent daemon so the new certs get issued — no need to re-enter secrets/address.
 */
class ManageCns extends Action
{
    private const VIEW_NAMESPACE = 'vault-mtls';

    private const AGENT_DIR = '/etc/vault-agent';

    private const MTLS_DIR = '/etc/nginx/mtls';

    private const TOKEN_DIR = '/run/vault-agent';

    private const DAEMON_NAME = 'vault-agent';

    public function name(): string
    {
        return 'Manage service names';
    }

    public function active(): bool
    {
        // Only available once the agent is installed (Install Agent has run).
        return $this->existingDaemon() !== null;
    }

    public function handle(Request $request): void
    {
        $this->validate($request);

        $daemon = $this->existingDaemon();
        if (! $daemon) {
            throw ValidationException::withMessages([
                'app_cns' => 'Vault Agent ist nicht installiert — bitte zuerst "Install Agent" ausführen.',
            ]);
        }

        /** @var SSH $ssh */
        $ssh = $this->server->ssh();

        $vaultAddr = $this->readVaultAddr($ssh);
        $cns = $this->parseCns((string) $request->input('app_cns'));

        // Re-render agent.hcl reusing the on-host vault address; the ad-root-ca.pem / role_id /
        // secret_id files stay exactly as they are.
        $hcl = $this->view('scripts.agent-hcl', [
            'vaultAddr' => $vaultAddr,
            'agentDir' => self::AGENT_DIR,
            'mtlsDir' => self::MTLS_DIR,
            'tokenDir' => self::TOKEN_DIR,
            'ldelim' => '{{',
            'rdelim' => '}}',
            'cns' => $cns,
        ])->render();

        $ssh->write(self::AGENT_DIR.'/agent.hcl', $hcl, 'root');
        $ssh->exec('sudo chmod 644 '.self::AGENT_DIR.'/agent.hcl', 'vault-mtls-chmod-config');

        // Restart so the agent re-reads agent.hcl and issues the (new) certs.
        app(ManageWorker::class)->restart($daemon);

        $request->session()->flash('success', 'Service-Namen aktualisiert — Agent wird neu gestartet, Zertifikate werden neu ausgestellt.');
    }

    /**
     * Read the Vault address back out of the existing agent.hcl (written by Install Agent).
     */
    private function readVaultAddr(SSH $ssh): string
    {
        $out = $ssh->exec(
            "sudo grep -oP 'address\\s*=\\s*\"\\K[^\"]+' ".self::AGENT_DIR.'/agent.hcl 2>/dev/null | head -n1 || true',
            'vault-mtls-read-addr'
        );

        $addr = trim($out);
        if ($addr === '') {
            throw ValidationException::withMessages([
                'app_cns' => 'Konnte die Vault-Adresse nicht aus agent.hcl lesen — bitte einmal "Install Agent" ausführen.',
            ]);
        }

        return $addr;
    }

    private function existingDaemon(): ?Worker
    {
        return $this->server->workers()
            ->whereNull('site_id')
            ->where('name', self::DAEMON_NAME)
            ->first();
    }

    /**
     * @return array<int, array{cn: string, short: string}>
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
            $cns[] = [
                'cn' => $cn,
                'short' => $short !== '' ? $short : 'service',
            ];
        }

        return $cns;
    }

    /**
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
            'app_cns' => ['required', 'string'],
        ])->validate();
    }
}
