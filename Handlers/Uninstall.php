<?php

namespace App\Vito\Plugins\NClouds\VaultMtls\Handlers;

use App\Actions\Worker\DeleteWorker;
use App\Helpers\SSH;
use App\Models\Worker;
use App\ServerFeatures\Action;
use Illuminate\Http\Request;

class Uninstall extends Action
{
    private const AGENT_DIR = '/etc/vault-agent';

    private const DAEMON_NAME = 'vault-agent';

    public function name(): string
    {
        return 'Uninstall';
    }

    public function active(): bool
    {
        return $this->daemon() instanceof Worker;
    }

    public function handle(Request $request): void
    {
        // Stop + delete the daemon. Worker::deleting removes the supervisor
        // program from the server via the process manager handler.
        $daemon = $this->daemon();
        if ($daemon instanceof Worker) {
            app(DeleteWorker::class)->delete($daemon);
        }

        // Remove agent config + credentials. Leave /etc/nginx/mtls intact
        // because nginx vhosts may still reference the issued certificates.
        /** @var SSH $ssh */
        $ssh = $this->server->ssh();
        $ssh->exec('sudo rm -rf '.self::AGENT_DIR, 'vault-mtls-uninstall-rm');

        $request->session()->flash('success', 'Vault Agent uninstalled. /etc/nginx/mtls was left in place.');
    }

    private function daemon(): ?Worker
    {
        return $this->server->workers()
            ->whereNull('site_id')
            ->where('name', self::DAEMON_NAME)
            ->first();
    }
}
