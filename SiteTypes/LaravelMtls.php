<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\SiteTypes;

use App\Actions\Webserver\GenerateNginxConfig;
use App\SiteTypes\Laravel;
use RuntimeException;

/**
 * Vitos `laravel`-Typ, um die mTLS-vhost-Ableitung erweitert.
 *
 * ## Warum ein Site-Typ und nicht `site.vhost_template`
 *
 * Bis 09/2026 schrieb `EnableMtls` die fertige Vorlage in `site.vhost_template`.
 * Das funktioniert, hat aber zwei Preise, und beide sind still:
 *
 *   1. **Die Vorlage friert ein.** Sie wird beim Einschalten aus Vitos Vorlage
 *      gebaut und liegt danach als Abzug in der Datenbank. Ändert ein
 *      Vito-Update die Vorlage — neue Direktive, Sicherheitskorrektur —, bekommt
 *      die Site das erst, wenn jemand „Enable" erneut ausführt. Bei mehreren
 *      Hosts vervielfacht sich das.
 *   2. **`vhost_template` schaltet Vitos PHP-Direktiven ab.** In
 *      `AbstractGenerateConfig` gilt `$phpEnabled = $isPhp && $site->vhost_template === null`
 *      — mit gesetzter Vorlage entfallen `client_max_body_size`,
 *      `fastcgi_read_timeout` und `PHP_VALUE`, und das Plugin musste sie aus
 *      `type_data.php.*` nachbauen. Vier Schlüsselnamen und eine Bedingung, die
 *      Vito jederzeit ändern darf; bei einer Änderung stehen dort leere Werte,
 *      also plötzlich 2 MB Uploadgrenze.
 *
 * Über den Typ-Haken entfällt beides. `AbstractGenerateConfig::getTemplate()`
 * fragt in dieser Reihenfolge:
 *
 *     $site->vhost_template   →   $site->type()->vhostTemplate($webserver)   →   defaultTemplate()
 *
 * Wir liefern in der Mitte. Damit bleibt `vhost_template` **null**, `$phpEnabled`
 * bleibt wahr, Vito erzeugt seine PHP-Direktiven weiter selbst — und unsere
 * Vorlage entsteht bei **jeder** Erzeugung neu aus Vitos aktueller.
 *
 * ## Warum dieser Typ `laravel` überschreibt statt daneben zu treten
 *
 * `RegisterSiteType::register()` prüft nicht auf Kollisionen; es überschreibt.
 * Das ist hier der Vorteil: `sites.type` bleibt für alle Bestandssites `laravel`,
 * es braucht keine Datenmigration. Und wird das Plugin deaktiviert, fällt
 * `laravel` auf Vitos eigenen Handler zurück — die Sites laufen weiter, nur ohne
 * mTLS-vhost. Ein eigener Typ `laravel-mtls` wäre nach dem Deaktivieren nicht
 * mehr auflösbar: `Site::type()` würfe, und dann wirft die **gesamte**
 * Sites-Liste 500 und `DeleteSite` scheitert ebenfalls.
 *
 * Preis: Überschreibt ein zweites Plugin denselben Typ, gewinnt das zuletzt
 * gebootete — lautlos. Bei eigenen Plugins überschaubar, gehört aber gewusst.
 */
class LaravelMtls extends Laravel
{
    /** Wo der Zustand je Site steht — `type_data`, nicht `vhost_template`. */
    public const SCHALTER = 'mtls_internal';

    /**
     * Der Anker in Vitos Vorlage: die schliessende Klammer des Server-Blocks.
     *
     * Nachgemessen gegen Vito 4.x — genau ein Treffer. Fehlt er oder gibt es ihn
     * mehrfach, hat sich das Layout der Kernvorlage geändert; dann wird
     * **geworfen** statt geraten. Ein falsch eingefügter Block nähme die Site
     * mitsamt Port 80 vom Netz, und zwar beim nächsten nginx-Reload — also lange
     * nach der Ursache.
     */
    private const ANKER = "}\n\n{{/server_blocks}}";

    /**
     * Die vhost-Vorlage dieser Site.
     *
     * Ohne eingeschaltetes mTLS genau das, was Vitos `laravel`-Typ liefert — der
     * Typ verhält sich dann in jeder Hinsicht wie das Original.
     */
    public function vhostTemplate(string $webserver): ?string
    {
        $einstellung = $this->mtlsEinstellung();

        if ($einstellung === null || $webserver !== 'nginx') {
            return parent::vhostTemplate($webserver);
        }

        return $this->mitMtls(
            parent::vhostTemplate($webserver) ?? app(GenerateNginxConfig::class)->defaultTemplate(),
            $einstellung,
        );
    }

    /** Ist mTLS für diese Site eingeschaltet — und mit welchen Pfaden? */
    public function mtlsEinstellung(): ?array
    {
        $wert = data_get($this->site->type_data, self::SCHALTER);

        if (! is_array($wert) || empty($wert['cert_path']) || empty($wert['ca_bundle_path'])) {
            return null;
        }

        return $wert;
    }

    /**
     * Den mTLS-Block vor die schliessende Klammer des Server-Blocks setzen.
     *
     * Die Direktiven müssen INNERHALB eines `server { }` stehen — anhängen genügt
     * nicht. Deshalb die Einfügung am Anker statt einer Verkettung.
     */
    private function mitMtls(string $vorlage, array $einstellung): string
    {
        $vorlage = str_replace("\r\n", "\n", $vorlage);

        if (substr_count($vorlage, self::ANKER) !== 1) {
            throw new RuntimeException(
                'Server-Block-Anker im Vito-vhost-Template nicht genau einmal gefunden — '
                .'das Layout der Kernvorlage hat sich geaendert. Das Plugin braucht ein Update; '
                .'bis dahin wuerde ein falsch eingefuegter mTLS-Block die Site beim naechsten '
                .'nginx-Reload vom Netz nehmen.'
            );
        }

        return str_replace(
            self::ANKER,
            trim($this->baustein($einstellung))."\n".self::ANKER,
            $vorlage,
        );
    }

    /** Der Baustein aus `views/templates/`, mit den Zertifikatspfaden dieser Site. */
    private function baustein(array $einstellung): string
    {
        $pfad = __DIR__.'/../views/templates/mtls-server-block.mustache';
        $inhalt = is_file($pfad) ? file_get_contents($pfad) : false;

        if ($inhalt === false) {
            throw new RuntimeException(
                "Plugin-Template {$pfad} fehlt — die Plugin-Installation ist unvollstaendig."
            );
        }

        return str_replace(
            ["\r\n", '__CERT_PATH__', '__CA_BUNDLE_PATH__'],
            ["\n", $einstellung['cert_path'], $einstellung['ca_bundle_path']],
            $inhalt,
        );
    }
}
