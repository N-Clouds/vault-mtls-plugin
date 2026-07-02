<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\SiteFeatures\Action;
use Illuminate\Http\Request;

class DisableMtls extends Action
{
    public function name(): string
    {
        return 'Disable';
    }

    public function active(): bool
    {
        // Always available: reverting is idempotent (regenerating already-stock
        // blocks is a no-op).
        return true;
    }

    public function handle(Request $request): void
    {
        // Rebuild the exact blocks EnableMtls appended to from Vito's stock
        // templates. This removes the 443/ssl + client-verify directives (port
        // resets to listen 80 only) and the /internal/ location.
        $this->site->webserver()->updateVHost(
            $this->site,
            regenerate: ['port', 'core', 'php'],
        );

        $request->session()->flash('success', 'mTLS disabled — vhost reverted to stock (port 80 only).');
    }
}
