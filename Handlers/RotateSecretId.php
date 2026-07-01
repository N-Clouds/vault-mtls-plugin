<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Actions\Worker\ManageWorker;
use App\Helpers\SSH;
use App\Models\Worker;
use App\ServerFeatures\Action;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class RotateSecretId extends Action
{
    private const AGENT_DIR = '/etc/vault-agent';

    private const DAEMON_NAME = 'vault-agent';

    public function name(): string
    {
        return 'Rotate secret_id';
    }

    public function active(): bool
    {
        return $this->daemon() instanceof Worker;
    }

    public function handle(Request $request): void
    {
        $this->validate($request);

        $secretId = trim((string) $request->input('secret_id'));

        /** @var SSH $ssh */
        $ssh = $this->server->ssh();

        $ssh->write(self::AGENT_DIR.'/secret_id', $secretId."\n", 'root');
        $ssh->exec('sudo chmod 600 '.self::AGENT_DIR.'/secret_id', 'vault-mtls-rotate-chmod');

        $daemon = $this->daemon();
        if ($daemon instanceof Worker) {
            app(ManageWorker::class)->restart($daemon);
        }

        $request->session()->flash('success', 'secret_id rotated and vault-agent restarted.');
    }

    private function daemon(): ?Worker
    {
        return $this->server->workers()
            ->whereNull('site_id')
            ->where('name', self::DAEMON_NAME)
            ->first();
    }

    private function validate(Request $request): void
    {
        Validator::make($request->all(), [
            'secret_id' => ['required', 'string'],
        ])->validate();
    }
}
