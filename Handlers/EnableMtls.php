<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Actions\Webserver\GenerateNginxConfig;
use App\DTOs\DynamicField;
use App\DTOs\DynamicForm;
use App\Helpers\SSH;
use App\SiteFeatures\Action;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\SiteTypes\LaravelMtls;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class EnableMtls extends Action
{
    private const MTLS_DIR = '/etc/nginx/mtls';

    private const MARKER = '# BEGIN vault-mtls';

    public function name(): string
    {
        return 'Enable';
    }

    public function active(): bool
    {
        // Always available: enabling is idempotent (the custom vhost template is rebuilt
        // from Vito's stock template on every run, so re-running never duplicates).
        return true;
    }

    public function form(): DynamicForm
    {
        $fields = [
            DynamicField::make('cert_name')
                ->text()
                ->label('Cert name')
                ->description('Base name of the agent-issued cert under /etc/nginx/mtls (defaults to the first DNS label of the site domain), e.g. `service1` → /etc/nginx/mtls/service1.pem'),
            DynamicField::make('ca_bundle_path')
                ->text()
                ->label('CA bundle path')
                ->default(self::MTLS_DIR.'/ca-bundle.pem')
                ->description('Path to the CA bundle nginx uses to verify client certificates (ssl_client_certificate).'),
        ];

        // Sites migrated from Vito 3.x have vhost generation disabled; without it,
        // updateVHost() is a no-op and the mTLS template would never reach the server.
        if (! $this->site->vhost_generation_enabled) {
            array_unshift($fields, DynamicField::make('alert-vhost-generation')
                ->alert()
                ->options(['type' => 'warning'])
                ->description('Für diese Site ist die Vhost-Generierung deaktiviert (v3-Migration). Zum Aktivieren von mTLS muss sie eingeschaltet werden — der Vhost wird dabei vollständig aus dem Vito-Template neu generiert; manuelle nginx-Anpassungen außerhalb von Vito gehen dabei verloren.'));

            $fields[] = DynamicField::make('enable_vhost_generation')
                ->checkbox()
                ->label('Vhost-Generierung für diese Site aktivieren')
                ->default(true)
                ->description('Pflicht für mTLS: ohne Vhost-Generierung kann Vito das mTLS-Template nicht auf den Server ausrollen.');
        }

        return DynamicForm::make($fields);
    }

    public function handle(Request $request): void
    {
        $this->validate($request);

        if ($this->site->webserver()::id() !== 'nginx') {
            throw ValidationException::withMessages([
                'cert_name' => 'mTLS /internal unterstützt nur nginx — diese Site läuft auf '.$this->site->webserver()::id().'.',
            ]);
        }

        // The mTLS feature manages TLS itself via the agent-issued certs. Vito-managed SSL
        // would add its own listen 443/ssl_certificate directives to the same server blocks
        // and collide with ours.
        if ($this->site->ssl_enabled) {
            throw ValidationException::withMessages([
                'cert_name' => 'Für diese Site ist Vito-SSL aktiv. mTLS /internal verwaltet TLS selbst über die Agent-Zertifikate — bitte zuerst SSL für die Site deaktivieren.',
            ]);
        }

        $certName = $this->resolveCertName($request);
        $certPath = self::MTLS_DIR.'/'.$certName.'.pem';
        $caBundlePath = trim((string) $request->input('ca_bundle_path')) ?: self::MTLS_DIR.'/ca-bundle.pem';

        /** @var SSH $ssh */
        $ssh = $this->site->server->ssh();

        // Pre-flight: refuse to inject `ssl_certificate` for a missing file, which
        // would make `nginx reload` fail and take the whole site (incl. port 80) down.
        $this->assertCertExists($ssh, $certPath);

        if (! $this->site->vhost_generation_enabled) {
            if (! $request->boolean('enable_vhost_generation')) {
                throw ValidationException::withMessages([
                    'enable_vhost_generation' => 'Ohne Vhost-Generierung ist updateVHost() ein No-Op — das mTLS-Template hätte keine Wirkung. Checkbox aktivieren oder die Vhost-Generierung in den Site-Einstellungen einschalten.',
                ]);
            }
            $this->site->vhost_generation_enabled = true;
        }

        /*
         | Der Zustand steht in `type_data`, die Vorlage entsteht zur Laufzeit.
         |
         | Bis 09/2026 wurde hier die fertige Vorlage in `site.vhost_template`
         | geschrieben. Das fror sie ein: Ein Vito-Update an der Kernvorlage erreichte
         | die Site erst, wenn jemand „Enable" erneut ausfuehrte. Und es schaltete
         | Vitos PHP-Direktiven ab (`$phpEnabled` verlangt `vhost_template === null`),
         | weshalb das Plugin sie aus `type_data.php.*` nachbauen musste.
         |
         | Jetzt liefert {@see LaravelMtls::vhostTemplate()} die Vorlage bei JEDER
         | Erzeugung neu aus Vitos aktueller. `vhost_template` bleibt null.
         |
         | Ausdruecklich zurueckgesetzt: Eine Site, die den alten Weg gegangen ist,
         | traegt dort noch den Abzug — und der gewinnt gegen den Typ-Haken
         | (`getTemplate()` fragt ihn zuerst).
         */
        $this->site->vhost_template = null;
        $this->site->jsonUpdate('type_data', LaravelMtls::SCHALTER, [
            'cert_path' => $certPath,
            'ca_bundle_path' => $caBundlePath,
        ], save: false);
        $this->site->save();

        $this->site->webserver()->updateVHost($this->site);

        $request->session()->flash('success', 'mTLS enabled for /internal/ (client cert '.$certPath.').');
    }

    /**
     * Build the site's custom Mustache vhost template: Vito's stock template (site-type
     * template if one exists, else the default) with the mTLS server-block snippet injected
     * before the closing brace of each server block. Always rebuilt from stock so re-running
     * Enable is idempotent and never duplicates — mirroring the v3 regenerate-then-append
     * semantics; a pre-existing foreign custom template is replaced.
     */
    private function buildVhostTemplate(string $certPath, string $caBundlePath): string
    {
        $base = $this->site->type()->vhostTemplate('nginx')
            ?? app(GenerateNginxConfig::class)->defaultTemplate();
        $base = str_replace("\r\n", "\n", $base);

        $snippet = file_get_contents(__DIR__.'/../views/templates/mtls-server-block.mustache');
        if ($snippet === false) {
            throw ValidationException::withMessages([
                'cert_name' => 'Plugin-Template views/templates/mtls-server-block.mustache fehlt — Plugin-Installation ist unvollständig.',
            ]);
        }
        $snippet = str_replace(["\r\n", '__CERT_PATH__', '__CA_BUNDLE_PATH__'], ["\n", $certPath, $caBundlePath], $snippet);

        $anchor = "}\n\n{{/server_blocks}}";
        if (substr_count($base, $anchor) !== 1) {
            throw ValidationException::withMessages([
                'cert_name' => 'Server-Block-Anker im Vito-Vhost-Template nicht gefunden — das Core-Template-Layout hat sich geändert; das Plugin braucht ein Update.',
            ]);
        }

        return str_replace($anchor, trim($snippet)."\n}\n\n{{/server_blocks}}", $base);
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

    private function validate(Request $request): void
    {
        Validator::make($request->all(), [
            'cert_name' => ['nullable', 'string', 'regex:/^[A-Za-z0-9._-]+$/'],
            // Rendered verbatim into the nginx vhost — absolute path, path chars only,
            // so no directives/newlines can be injected.
            'ca_bundle_path' => ['nullable', 'string', 'regex:/^\/[A-Za-z0-9._\/-]+$/'],
            'enable_vhost_generation' => ['nullable', 'boolean'],
        ])->validate();
    }
}
