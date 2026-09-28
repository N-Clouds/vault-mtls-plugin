<?php

declare(strict_types=1);

use App\Actions\Webserver\GenerateNginxConfig;
use App\Models\Site;
use App\SiteTypes\Laravel;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Plugin;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\SiteTypes\LaravelMtls;

/**
 * Die vhost-Ableitung — der Teil, der eine Site vom Netz nehmen kann.
 *
 * ## Warum genau hier Tests stehen
 *
 * Ein falsch eingefügter Block macht keinen Ärger beim Speichern, sondern beim
 * **nächsten nginx-Reload** — und dann ist die Site komplett weg, inklusive Port 80,
 * über den der Plesk-Proxy den öffentlichen Verkehr schickt. Die Ursache liegt dann
 * Stunden zurück.
 *
 * Die Ableitung hängt an zwei Dingen in Vitos Kernvorlage, die keine zugesagte
 * Schnittstelle sind:
 *
 *   1. dem Anker `}` + Leerzeile + `{{/server_blocks}}` — er muss **genau einmal**
 *      vorkommen;
 *   2. dem Token `@@VITO_PHP_VALUE@@`, den `AbstractGenerateConfig::generate()`
 *      global über die gerenderte Ausgabe ersetzt.
 *
 * Ändert ein Vito-Update eines davon, soll **dieser Test** rot werden — nicht ein
 * Kunde anrufen.
 *
 * Aufruf aus dem Vito-Verzeichnis:
 *
 *     php artisan test app/Vito/Plugins/NClouds/VaultMtlsPlugin/tests
 */
uses(Tests\TestCase::class);

beforeEach(function () {
    (new Plugin)->boot();
});

/** Eine nicht gespeicherte Site — die Ableitung braucht keine Datenbank. */
function siteMitMtls(?array $einstellung): Site
{
    return new Site([
        'type' => 'laravel',
        'type_data' => $einstellung === null ? [] : [LaravelMtls::SCHALTER => $einstellung],
    ]);
}

function standardEinstellung(): array
{
    return [
        'cert_path' => '/etc/nginx/mtls/cms.pem',
        'ca_bundle_path' => '/etc/nginx/mtls/ca-bundle.pem',
    ];
}

it('haengt sich in Vitos laravel-Typ ein, ohne ihn zu ersetzen', function () {
    /*
     * Nur der Handler wird getauscht. Beschriftung und Anlegen-Formular bleiben
     * Vitos — eine Kopie davon im Plugin würde bei jedem Vito-Update driften und
     * der Dialog verlöre still Felder (Vitos Formular hat sieben).
     */
    $typ = config('site.types.laravel');

    expect($typ['handler'])->toBe(LaravelMtls::class)
        ->and($typ['label'])->toBe('Laravel')
        ->and($typ['form'])->not->toBeEmpty();
});

it('erbt von Vitos Laravel-Typ, damit type_data kompatibel bleibt', function () {
    // Deshalb braucht kein Bestandsmandant eine Datenmigration: derselbe
    // type_data-Vertrag, nur ein zusaetzlicher Schalter.
    expect(siteMitMtls(null)->type())->toBeInstanceOf(LaravelMtls::class)
        ->and(siteMitMtls(null)->type())->toBeInstanceOf(Laravel::class);
});

it('liefert ohne eingeschaltetes mTLS genau Vitos Vorlage', function () {
    /*
     * Das ist die Zusage, die den Handler-Tausch vertretbar macht: Eine Site ohne
     * mTLS verhaelt sich in JEDER Hinsicht wie vorher. Waere das nicht so, haetten
     * wir mit dem Tausch alle Laravel-Sites des Servers angefasst.
     */
    $abgeleitet = siteMitMtls(null)->type()->vhostTemplate('nginx');
    $vitoEigen = (new Laravel(siteMitMtls(null)))->vhostTemplate('nginx');

    expect($abgeleitet)->toBe($vitoEigen)
        ->and((string) $abgeleitet)->not->toContain('# BEGIN vault-mtls');
});

it('fuegt den mTLS-Block genau einmal ein', function () {
    $vorlage = siteMitMtls(standardEinstellung())->type()->vhostTemplate('nginx');

    expect($vorlage)->toBeString()
        ->and(substr_count($vorlage, '# BEGIN vault-mtls'))->toBe(1)
        ->and(substr_count($vorlage, '# END vault-mtls'))->toBe(1)
        // Die Zertifikatspfade dieser Site, nicht die Platzhalter.
        ->and($vorlage)->toContain('ssl_certificate /etc/nginx/mtls/cms.pem;')
        ->and($vorlage)->toContain('ssl_client_certificate /etc/nginx/mtls/ca-bundle.pem;')
        ->and($vorlage)->not->toContain('__CERT_PATH__')
        ->and($vorlage)->not->toContain('__CA_BUNDLE_PATH__');
});

it('erzeugt keine doppelten Direktiven', function () {
    /*
     * DER Test dieser Datei.
     *
     * Bis 09/2026 baute das Plugin `client_max_body_size` selbst nach, weil ein
     * gesetztes `site.vhost_template` Vitos PHP-Direktiven abschaltete
     * (`$phpEnabled = $isPhp && $site->vhost_template === null`). Über den Typ-Haken
     * bleibt `vhost_template` null — Vito emittiert sie also WIEDER. Ein
     * verbliebener Nachbau ergaebe die Direktive zweimal, und nginx verweigert dann
     * den Start.
     */
    $vorlage = siteMitMtls(standardEinstellung())->type()->vhostTemplate('nginx');

    /*
     | Gezaehlt wird die EMITTIERENDE Form, nicht das Wort.
     |
     | In Vitos Vorlage steht `client_max_body_size` viermal in einer Zeile —
     | als Mustache-Abschnittsmarken (`{{#…}}`, `{{…}}`, `{{/…}}`) — und einmal
     | in unserem Kommentar. Nur `client_max_body_size {{` ist die Stelle, die
     | im gerenderten vhost tatsaechlich eine Direktive erzeugt.
     */
    expect(substr_count($vorlage, 'client_max_body_size {{'))->toBe(1)
        // Der Nachbau aus den type_data-Schluesseln ist restlos weg.
        ->and($vorlage)->not->toContain('type_data.php.max_upload_size')
        ->and($vorlage)->not->toContain('type_data.php.memory_limit')
        // Stattdessen Vitos eigener Token — einmal von Vito, einmal von uns.
        ->and(substr_count($vorlage, '@@VITO_PHP_VALUE@@'))->toBe(2);
});

it('laesst die geschweiften Klammern ausgeglichen', function () {
    // Eine unausgeglichene Klammer ist der Fehler, der die Site beim Reload
    // mitsamt Port 80 vom Netz nimmt.
    $vorlage = siteMitMtls(standardEinstellung())->type()->vhostTemplate('nginx');

    expect(substr_count($vorlage, '{'))->toBe(substr_count($vorlage, '}'));
});

it('setzt den Block INNERHALB des Server-Blocks, nicht dahinter', function () {
    // Die Direktiven muessen in ein `server { }` — anhaengen genuegt nicht, und
    // der Fehler waere erst im gerenderten vhost sichtbar.
    $vorlage = siteMitMtls(standardEinstellung())->type()->vhostTemplate('nginx');

    $beginn = strpos($vorlage, '# BEGIN vault-mtls');
    $blockEnde = strpos($vorlage, '{{/server_blocks}}');

    expect($beginn)->toBeLessThan($blockEnde);
});

it('bemerkt es, wenn Vito den Anker aendert', function () {
    /*
     * Der Anker ist das eine verbliebene Interna. Er kommt in Vito 4.x genau
     * einmal vor — bleibt das so, ist dieser Test gruen; aendert Vito das Layout
     * der Kernvorlage, wird er rot, und zwar BEVOR jemand deployt.
     */
    $vitoVorlage = str_replace("\r\n", "\n", app(GenerateNginxConfig::class)->defaultTemplate());

    expect(substr_count($vitoVorlage, "}\n\n{{/server_blocks}}"))->toBe(1);
});

it('ruehrt Caddy nicht an', function () {
    // Der Baustein ist nginx-Syntax. Fuer Caddy muss der Typ Vitos Verhalten
    // unveraendert durchreichen, statt eine kaputte Konfiguration zu erzeugen.
    $mitMtls = siteMitMtls(standardEinstellung())->type()->vhostTemplate('caddy');
    $ohne = (new Laravel(siteMitMtls(null)))->vhostTemplate('caddy');

    expect($mitMtls)->toBe($ohne);
});

it('laesst sich zweimal booten, ohne zu werfen', function () {
    /*
     * DER Test, der am 28.09.2026 gefehlt hat.
     *
     * `php artisan optimize` bootet die Anwendung ZWEIMAL im selben Prozess:
     * `config:cache` schreibt die von uns angereicherte Konfiguration in den
     * Cache, danach laedt `route:cache` ueber `getFreshApplication()` genau
     * diesen Cache und bootet die Plugins erneut. Vier von Vitos
     * Registrierungen werfen dann „already exists" — und das Deploy bricht mit
     * einem Stapel ab, in dem die eigentliche Meldung gar nicht auftaucht.
     *
     * `beforeEach` hat bereits einmal gebootet; der zweite Aufruf hier ist der
     * Fall, der in Produktion gescheitert ist.
     */
    expect(fn () => (new Plugin)->boot())->not->toThrow(RuntimeException::class);

    // Und die Registrierungen stehen danach genau einmal da, nicht doppelt.
    expect(config('server.features.vault-mtls'))->not->toBeNull()
        ->and(config('server.features.vault-mtls.actions'))->toHaveCount(4)
        ->and(config('site.types.laravel.features.mtls-internal.actions'))->toHaveCount(2)
        ->and(config('site.types.laravel.handler'))->toBe(LaravelMtls::class);
});
