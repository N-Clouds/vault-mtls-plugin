<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Helpers\SSH;
use App\SiteFeatures\Action;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class EnableMtls extends Action
{
    private const VIEW_NAMESPACE = 'vault-mtls';

    private const MTLS_DIR = '/etc/nginx/mtls';

    public function name(): string
    {
        return 'Enable';
    }

    public function active(): bool
    {
        // Always available: enabling is idempotent (blocks are regenerated to stock
        // before the mTLS snippets are re-appended, so re-running never duplicates).
        return true;
    }

    public function handle(Request $request): void
    {
        $this->validate($request);

        $certName = $this->resolveCertName($request);
        $certPath = self::MTLS_DIR.'/'.$certName.'.pem';
        $caBundlePath = trim((string) $request->input('ca_bundle_path')) ?: self::MTLS_DIR.'/ca-bundle.pem';

        /** @var SSH $ssh */
        $ssh = $this->site->server->ssh();

        // Pre-flight: refuse to inject `ssl_certificate` for a missing file, which
        // would make `nginx reload` fail and take the whole site (incl. port 80) down.
        $this->assertCertExists($ssh, $certPath);

        $portSnippet = $this->view('scripts.vhost-mtls-port', [
            'certPath' => $certPath,
            'caBundlePath' => $caBundlePath,
        ])->render();

        $locationSnippet = $this->view('scripts.vhost-mtls-location', [])->render();

        // Regenerate the affected blocks to stock first (idempotent re-enable), then
        // append the server-level TLS + client-verify directives and the /internal/
        // location inside the server block. Port 80 stays intact (Plesk uses it).
        $this->site->webserver()->updateVHost(
            $this->site,
            regenerate: ['port', 'core'],
            append: [
                'port' => $portSnippet,
                'core' => $locationSnippet,
            ],
        );

        $request->session()->flash('success', 'mTLS enabled for /internal/ (client cert '.$certPath.').');
    }

    /**
     * Resolve the cert base name: explicit form input, else the first DNS label
     * of the site's primary domain (e.g. service1.example.local -> service1).
     */
    private function resolveCertName(Request $request): string
    {
        $input = trim((string) $request->input('cert_name'));
        if ($input !== '') {
            return $input;
        }

        return Str::of((string) $this->site->domain)->before('.')->toString();
    }

    /**
     * @throws ValidationException
     */
    private function assertCertExists(SSH $ssh, string $certPath): void
    {
        $result = $ssh->exec(
            'test -f '.escapeshellarg($certPath).' && echo VITO_CERT_PRESENT || echo VITO_CERT_MISSING',
            'vault-mtls-preflight-cert',
            $this->site->id
        );

        if (! Str::contains($result, 'VITO_CERT_PRESENT')) {
            throw ValidationException::withMessages([
                'cert_name' => 'Client cert not found at '.$certPath
                    .' — run Install Agent first and wait for issuance before enabling mTLS.',
            ]);
        }
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
            'cert_name' => ['nullable', 'string', 'regex:/^[A-Za-z0-9._-]+$/'],
            'ca_bundle_path' => ['nullable', 'string'],
        ])->validate();
    }
}
