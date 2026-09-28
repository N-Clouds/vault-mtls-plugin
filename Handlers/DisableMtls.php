<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\DTOs\DynamicField;
use App\DTOs\DynamicForm;
use App\SiteFeatures\Action;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\SiteTypes\LaravelMtls;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class DisableMtls extends Action
{
    public function name(): string
    {
        return 'Disable';
    }

    public function active(): bool
    {
        // Always available: reverting is idempotent (clearing an already-empty
        // custom template is a no-op).
        return true;
    }

    public function form(): ?DynamicForm
    {
        // Sites migrated from Vito 3.x have vhost generation disabled; without it,
        // updateVHost() is a no-op and the mTLS directives would stay in the live vhost.
        if ($this->site->vhost_generation_enabled) {
            return null;
        }

        return DynamicForm::make([
            DynamicField::make('alert-vhost-generation')
                ->alert()
                ->options(['type' => 'warning'])
                ->description('Für diese Site ist die Vhost-Generierung deaktiviert (v3-Migration). Zum Entfernen von mTLS muss sie eingeschaltet werden — der Vhost wird dabei vollständig aus dem Vito-Template neu generiert; manuelle nginx-Anpassungen außerhalb von Vito gehen dabei verloren.'),
            DynamicField::make('enable_vhost_generation')
                ->checkbox()
                ->label('Vhost-Generierung für diese Site aktivieren')
                ->default(true)
                ->description('Pflicht: ohne Vhost-Generierung kann Vito den Stock-Vhost nicht ausrollen — die mTLS-Direktiven blieben aktiv.'),
        ]);
    }

    public function handle(Request $request): void
    {
        if (! $this->site->vhost_generation_enabled) {
            if (! $request->boolean('enable_vhost_generation')) {
                throw ValidationException::withMessages([
                    'enable_vhost_generation' => 'Ohne Vhost-Generierung ist updateVHost() ein No-Op — die mTLS-Direktiven blieben im Live-Vhost. Checkbox aktivieren oder die Vhost-Generierung in den Site-Einstellungen einschalten.',
                ]);
            }
            $this->site->vhost_generation_enabled = true;
        }

        // Clearing the custom template makes Vito regenerate the vhost from its stock
        // template — removing the 443/ssl + client-verify directives (port resets to
        // listen 80 only) and the /internal/ location.
        /*
         | Beides zuruecknehmen: den Schalter in `type_data` (neuer Weg) UND einen
         | etwaigen Abzug in `vhost_template` (alter Weg, vor 09/2026). Nur eines
         | davon zu loeschen liesse die mTLS-Direktiven im Live-vhost stehen.
         */
        $this->site->jsonForget('type_data', LaravelMtls::SCHALTER, save: false);
        $this->site->vhost_template = null;
        $this->site->save();

        $this->site->webserver()->updateVHost($this->site);

        $request->session()->flash('success', 'mTLS disabled — vhost reverted to stock (port 80 only).');
    }
}
