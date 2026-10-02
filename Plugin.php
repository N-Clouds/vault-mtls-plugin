<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin;

use App\DTOs\DynamicField;
use App\DTOs\DynamicForm;
use App\Plugins\AbstractPlugin;
use App\Plugins\RegisterServerFeature;
use App\Plugins\RegisterServerFeatureAction;
use App\Plugins\RegisterSiteFeature;
use App\Plugins\RegisterSiteFeatureAction;
use App\Plugins\RegisterViews;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\DisableMtls;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\EnableMtls;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\InstallAgent;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\ManageCns;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\RotateSecretId;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\Uninstall;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\SiteTypes\LaravelMtls;
use RuntimeException;

class Plugin extends AbstractPlugin
{
    protected string $name = 'Vault mTLS';

    protected string $description = 'Rolls out a HashiCorp Vault Agent that issues and auto-renews PKI certificates for nginx mTLS on a managed server.';

    public function boot(): void
    {
        RegisterViews::make('vault-mtls')
            ->path(__DIR__.'/views')
            ->register();

        if ($this->neu('server.features.vault-mtls')) {
                RegisterServerFeature::make('vault-mtls')
                ->label('Vault mTLS')
                ->description('Install and manage a Vault Agent daemon that fetches short-lived PKI certificates for nginx client-certificate authentication.')
                ->register();
        }

        if ($this->neu('server.features.vault-mtls.actions.install-agent')) {
                RegisterServerFeatureAction::make('vault-mtls', 'install-agent')
                ->label('Install Agent')
                ->form(DynamicForm::make([
                    DynamicField::make('vault_addr')
                        ->text()
                        ->label('Vault address')
                        ->placeholder('https://vault.example.local:8200')
                        ->description('HA-Cluster: der CLUSTER-Endpunkt (Lastverteiler bzw. der `active`-Name), NICHT ein einzelner Knoten — nach einer Leader-Wahl redet der Agent sonst mit einem Standby. Base URL of the Vault server the agent authenticates against. Include the API port — Vault listens on 8200. If you omit the port, :8200 is assumed (an explicit port such as :443 for an nginx TLS proxy is respected). Re-install: leave empty to reuse the address already configured on the host.'),
                    DynamicField::make('ad_root_ca')
                        ->textarea()
                        ->label('AD Root CA (PEM)')
                        ->placeholder("-----BEGIN CERTIFICATE-----\n...")
                        ->description('PEM of the AD Root CA. Used as the agent ca_cert to trust Vault, and referenced for the nginx client-verify bundle. Re-install: leave empty to keep the CA file already on the host.'),
                    DynamicField::make('role_id')
                        ->text()
                        ->label('AppRole role_id')
                        ->description('Vault AppRole role_id used for auto-auth. Re-install: leave empty to keep the existing file.'),
                    DynamicField::make('secret_id')
                        ->password()
                        ->label('AppRole secret_id')
                        ->description('Vault AppRole secret_id. Stored at /etc/vault-agent/secret_id (chmod 600). Re-install: leave empty to keep the existing file.'),
                    DynamicField::make('app_cns')
                        ->textarea()
                        ->label('Service common names')
                        ->placeholder("service1.example.local\nservice2.example.local")
                        ->description('Newline- or comma-separated list of service hostnames. One certificate is issued and auto-renewed per CN. Re-install: leave empty to keep the current CN list from agent.hcl.'),
                    DynamicField::make('hmac_kv_path')
                        ->text()
                        ->label('Event-bus HMAC KV path (optional)')
                        ->placeholder('secret/data/eventbus/hmac')
                        ->description('If set, the agent also renders the event-bus HMAC signing secret from this Vault KV v2 path to /etc/nginx/mtls/eventbus-hmac (mirrored into each app HOME). The AppRole policy must allow read on this path. Re-install: leave empty to keep the current setting, enter "-" to remove it. First install: leave empty to skip.'),
                ]))
                ->handler(InstallAgent::class)
                ->register();
        }

        if ($this->neu('server.features.vault-mtls.actions.manage-cns')) {
                // Kein statisches Formular: Vito nimmt ein registriertes Formular immer vor
                // ManageCns::form() (Server::features()), und nur der Handler kennt den Server —
                // er fuellt die CN-Liste aus dem Zustand vor, statt sie abtippen zu lassen.
                RegisterServerFeatureAction::make('vault-mtls', 'manage-cns')
                ->label('Manage service names')
                ->handler(ManageCns::class)
                ->register();
        }

        // Vito cached die Config MIT den Plugin-Registrierungen (`php artisan optimize` in
        // scripts/update.sh bootet die Plugins). Ein Plugin-Update raeumt diesen Cache nicht
        // auf: Dann steht hier noch das statische Formular aus Releases vor 3.1.0, `neu()`
        // laesst die Registrierung oben aus, und Server::features() nimmt das alte Formular
        // vor ManageCns::form(). Deshalb bei jedem Boot ausdruecklich leeren.
        $actions = config('server.features.vault-mtls.actions', []);
        if (isset($actions['manage-cns']) && ($actions['manage-cns']['form'] ?? []) !== []) {
            $actions['manage-cns']['form'] = [];
            $actions['manage-cns']['handler'] = ManageCns::class;
            config(['server.features.vault-mtls.actions' => $actions]);
        }

        if ($this->neu('server.features.vault-mtls.actions.rotate-secret-id')) {
                RegisterServerFeatureAction::make('vault-mtls', 'rotate-secret-id')
                ->label('Rotate secret_id')
                ->form(DynamicForm::make([
                    DynamicField::make('secret_id')
                        ->password()
                        ->label('New AppRole secret_id')
                        ->description('Overwrites /etc/vault-agent/secret_id (chmod 600) and restarts the vault-agent daemon.'),
                ]))
                ->handler(RotateSecretId::class)
                ->register();
        }

        if ($this->neu('server.features.vault-mtls.actions.uninstall')) {
                RegisterServerFeatureAction::make('vault-mtls', 'uninstall')
                ->label('Uninstall')
                ->handler(Uninstall::class)
                ->register();
        }

        // Per-site feature: inject nginx client-certificate verification so that
        // /internal/* requires a valid client cert, while public traffic (port 80
        // via the Plesk reverse proxy) keeps working. TLS + mTLS point at the
        // agent-managed cert files under /etc/nginx/mtls (NOT Vito's SSL model).
        // Registered for the 'laravel' site type, mirroring core Modern Deployment.
        // The forms live on the handlers (form() method) because their fields depend
        // on per-site state (vhost_generation_enabled for v3-migrated sites).
        /*
         | Vitos `laravel`-Typ um die vhost-Ableitung erweitern.
         |
         | NICHT ueber RegisterSiteType: Das ersetzt den GANZEN Eintrag, also auch
         | Beschriftung und Anlegen-Formular. Vitos Formular hat sieben Felder
         | (PHP-Fassung, Source Control, Web Directory, Repository, Branch, composer,
         | Paketverwalter) — eine Kopie davon hier wuerde bei jedem Vito-Update
         | driften, und der Anlegen-Dialog verloere still Felder.
         |
         | Stattdessen wird genau EIN Feld getauscht: der Handler. Das ist derselbe
         | Config-Schluessel, den RegisterSiteType schreibt.
         |
         | Reihenfolge stimmt: Vitos SiteTypeServiceProvider::boot() registriert
         | `laravel`, BootPlugins laeuft in app->booted() und damit danach.
         |
         | Wird das Plugin deaktiviert, faellt `laravel` auf Vitos eigenen Handler
         | zurueck — Sites laufen weiter, nur ohne mTLS-vhost. Genau deshalb kein
         | eigener Typ: der waere nach dem Deaktivieren nicht mehr aufloesbar, und
         | dann wirft die gesamte Sites-Liste 500.
         */
        if (config('site.types.laravel') === null) {
            throw new RuntimeException(
                'Vito hat keinen Site-Typ "laravel" registriert — das Plugin kann seine '
                .'vhost-Ableitung nicht einhaengen. Vito-Fassung pruefen.',
            );
        }

        config(['site.types.laravel.handler' => LaravelMtls::class]);

        if ($this->neu('site.types.laravel.features.mtls-internal')) {
                RegisterSiteFeature::make('laravel', 'mtls-internal')
                ->label('mTLS /internal')
                ->description('Require a valid client certificate for /internal/* using the agent-issued certs under /etc/nginx/mtls. Installs a custom vhost template; keeps port 80 (Plesk reverse proxy) intact.')
                ->register();
        }

        if ($this->neu('site.types.laravel.features.mtls-internal.actions.enable')) {
                RegisterSiteFeatureAction::make('laravel', 'mtls-internal', 'enable')
                ->label('Enable')
                ->handler(EnableMtls::class)
                ->register();
        }

        if ($this->neu('site.types.laravel.features.mtls-internal.actions.disable')) {
                RegisterSiteFeatureAction::make('laravel', 'mtls-internal', 'disable')
                ->label('Disable')
                ->handler(DisableMtls::class)
                ->register();
        }
    }

    /**
     * Ist diese Registrierung noch nicht vorhanden?
     *
     * ## Warum boot() mehrfach laufen muss
     *
     * `php artisan optimize` bootet die Anwendung ZWEIMAL im selben Prozess:
     * `config:cache` laeuft zuerst — dabei laeuft `BootPlugins`, unsere
     * Registrierungen landen im Speicher, und `config:cache` schreibt genau
     * diese angereicherte Konfiguration nach `bootstrap/cache/config.php`.
     * Danach ruft `route:cache` ueber `getFreshApplication()` eine frische
     * Anwendung auf, die den Cache laedt — in dem unsere Eintraege schon
     * stehen — und bootet die Plugins erneut.
     *
     * Vier von Vitos Registrierungen werfen dann:
     * `RegisterServerFeature`, `RegisterServerFeatureAction`,
     * `RegisterSiteFeature` und `RegisterSiteFeatureAction` melden
     * „already exists". `RegisterViews` und `RegisterSiteType` ueberschreiben
     * dagegen still, die brauchen keine Wache.
     *
     * Geprueft wird je Registrierung und nicht einmal pauschal am Anfang:
     * Kommt spaeter eine Aktion dazu, soll sie sich auch dann eintragen,
     * wenn die uebrigen schon im Cache stehen.
     */
    private function neu(string $pfad): bool
    {
        return config($pfad) === null;
    }
}
