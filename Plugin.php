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

class Plugin extends AbstractPlugin
{
    protected string $name = 'Vault mTLS';

    protected string $description = 'Rolls out a HashiCorp Vault Agent that issues and auto-renews PKI certificates for nginx mTLS on a managed server.';

    public function boot(): void
    {
        RegisterViews::make('vault-mtls')
            ->path(__DIR__.'/views')
            ->register();

        RegisterServerFeature::make('vault-mtls')
            ->label('Vault mTLS')
            ->description('Install and manage a Vault Agent daemon that fetches short-lived PKI certificates for nginx client-certificate authentication.')
            ->register();

        RegisterServerFeatureAction::make('vault-mtls', 'install-agent')
            ->label('Install Agent')
            ->form(DynamicForm::make([
                DynamicField::make('vault_addr')
                    ->text()
                    ->label('Vault address')
                    ->default('https://vault.example.local')
                    ->description('Base URL of the Vault server the agent authenticates against.'),
                DynamicField::make('ad_root_ca')
                    ->textarea()
                    ->label('AD Root CA (PEM)')
                    ->placeholder("-----BEGIN CERTIFICATE-----\n...")
                    ->description('PEM of the AD Root CA. Used as the agent ca_cert to trust Vault, and referenced for the nginx client-verify bundle.'),
                DynamicField::make('role_id')
                    ->text()
                    ->label('AppRole role_id')
                    ->description('Vault AppRole role_id used for auto-auth.'),
                DynamicField::make('secret_id')
                    ->password()
                    ->label('AppRole secret_id')
                    ->description('Vault AppRole secret_id. Stored at /etc/vault-agent/secret_id (chmod 600).'),
                DynamicField::make('app_cns')
                    ->textarea()
                    ->label('Service common names')
                    ->placeholder("service1.example.local\nservice2.example.local")
                    ->description('Newline- or comma-separated list of service hostnames. One certificate is issued and auto-renewed per CN.'),
                DynamicField::make('hmac_kv_path')
                    ->text()
                    ->label('Event-bus HMAC KV path (optional)')
                    ->placeholder('secret/data/eventbus/hmac')
                    ->description('Leave empty to skip. If set, the agent also renders the event-bus HMAC signing secret from this Vault KV v2 path to /etc/nginx/mtls/eventbus-hmac (mirrored into each app HOME). The AppRole policy must allow read on this path.'),
            ]))
            ->handler(InstallAgent::class)
            ->register();

        RegisterServerFeatureAction::make('vault-mtls', 'manage-cns')
            ->label('Manage service names')
            ->form(DynamicForm::make([
                DynamicField::make('app_cns')
                    ->textarea()
                    ->label('Service common names')
                    ->placeholder("service1.example.local\nservice2.example.local")
                    ->description('Vollständige Liste (ersetzt die bestehende). Vault-Adresse, AD Root CA und AppRole-Credentials werden vom Host wiederverwendet — kein erneutes Eintragen nötig.'),
            ]))
            ->handler(ManageCns::class)
            ->register();

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

        RegisterServerFeatureAction::make('vault-mtls', 'uninstall')
            ->label('Uninstall')
            ->handler(Uninstall::class)
            ->register();

        // Per-site feature: inject nginx client-certificate verification so that
        // /internal/* requires a valid client cert, while public traffic (port 80
        // via the Plesk reverse proxy) keeps working. TLS + mTLS point at the
        // agent-managed cert files under /etc/nginx/mtls (NOT Vito's SSL model).
        // Registered for the 'laravel' site type, mirroring core Modern Deployment.
        RegisterSiteFeature::make('laravel', 'mtls-internal')
            ->label('mTLS /internal')
            ->description('Require a valid client certificate for /internal/* using the agent-issued certs under /etc/nginx/mtls. Keeps port 80 (Plesk reverse proxy) intact.')
            ->register();

        RegisterSiteFeatureAction::make('laravel', 'mtls-internal', 'enable')
            ->label('Enable')
            ->form(DynamicForm::make([
                DynamicField::make('cert_name')
                    ->text()
                    ->label('Cert name')
                    ->description('Base name of the agent-issued cert under /etc/nginx/mtls (defaults to the first DNS label of the site domain), e.g. `service1` → /etc/nginx/mtls/service1.pem'),
                DynamicField::make('ca_bundle_path')
                    ->text()
                    ->label('CA bundle path')
                    ->default('/etc/nginx/mtls/ca-bundle.pem')
                    ->description('Path to the CA bundle nginx uses to verify client certificates (ssl_client_certificate).'),
            ]))
            ->handler(EnableMtls::class)
            ->register();

        RegisterSiteFeatureAction::make('laravel', 'mtls-internal', 'disable')
            ->label('Disable')
            ->handler(DisableMtls::class)
            ->register();
    }
}
