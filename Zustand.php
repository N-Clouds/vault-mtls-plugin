<?php

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin;

use App\Helpers\SSH;
use App\Models\Server;

/**
 * Der Zustand des Agents je Server — in Vito, nicht in `agent.hcl`.
 *
 * ## Warum es diese Klasse gibt
 *
 * Bis 09/2026 war die geschriebene `agent.hcl` gleichzeitig der Zustandsspeicher:
 * `InstallAgent` und `ManageCns` lasen Vault-Adresse, CN-Liste und HMAC-KV-Pfad
 * per `grep -oP` aus der Datei zurück, die sie selbst erzeugt hatten. Einer der
 * Anker war ein **Kommentartext**:
 *
 *     grep -oP '# Event-bus HMAC signing secret from Vault KV \(\K[^)]+'
 *
 * Wer diesen Kommentar im Blade-Template umformuliert, nimmt `ManageCns` den
 * KV-Pfad weg. Die HMAC-Vorlage verschwindet dann aus der neu gerenderten
 * `agent.hcl`, das Geheimnis wird nicht mehr erneuert — und es fällt erst bei der
 * nächsten Rotation auf, also Tage später und ohne Bezug zur Ursache. Genau diese
 * Fehlerklasse (ein Signiergeheimnis, das still nicht mehr passt) hat am
 * 27.09.2026 einen Abend gekostet.
 *
 * ## Wo der Zustand jetzt liegt
 *
 * In `servers.feature_data['vault-mtls']` — dieselbe Ablage, die Vito für
 * Server-Features benutzt (`ManagePasswordAuth`, `DetectSecurityJob`:
 * `$server->jsonUpdate('feature_data', 'security', …)`). Damit ist er
 * strukturiert, überlebt jedes Neurendern und hängt an keinem Kommentar.
 *
 * ## Warum die Greps bleiben
 *
 * Als **Rückfall** für Hosts, die vor dieser Änderung eingerichtet wurden: Dort
 * steht in `feature_data` nichts, und die Wahrheit liegt weiter in `agent.hcl`.
 * Wird `lesen()` fündig, schreibt es das Gelesene gleich nach Vito — der erste
 * `Install Agent` oder `Manage service names` auf einem Bestandshost holt den
 * Zustand also von selbst herüber, ohne Migrationsschritt.
 */
class Zustand
{
    public const SCHLUESSEL = 'vault-mtls';

    private const AGENT_DIR = '/etc/vault-agent';

    /**
     * Was wir über diesen Server wissen — aus Vito, sonst aus `agent.hcl`.
     *
     * @return array{vault_addr: string, cns: array<int, string>, hmac_kv_path: string}
     */
    /**
     * Nur der in Vito gespeicherte Stand — ohne Host-Zugriff. Fuer Formulare, die beim
     * Oeffnen der Features-Seite gebaut werden: Dort darf keine SSH-Sitzung entstehen.
     *
     * @return array{vault_addr: string, cns: array<int, string>, hmac_kv_path: string}|null
     */
    public static function gespeichert(Server $server): ?array
    {
        $gespeichert = $server->feature_data[self::SCHLUESSEL] ?? null;

        if (! is_array($gespeichert) || ! isset($gespeichert['vault_addr'])) {
            return null;
        }

        return [
            'vault_addr'   => (string) $gespeichert['vault_addr'],
            'cns'          => array_values((array) ($gespeichert['cns'] ?? [])),
            'hmac_kv_path' => (string) ($gespeichert['hmac_kv_path'] ?? ''),
        ];
    }

    public static function lesen(Server $server): array
    {
        $gespeichert = $server->feature_data[self::SCHLUESSEL] ?? null;

        if (is_array($gespeichert) && isset($gespeichert['vault_addr'])) {
            return [
                'vault_addr'   => (string) $gespeichert['vault_addr'],
                'cns'          => array_values((array) ($gespeichert['cns'] ?? [])),
                'hmac_kv_path' => (string) ($gespeichert['hmac_kv_path'] ?? ''),
            ];
        }

        $vomHost = self::vomHost($server);

        // Einmal herüberholen, damit der nächste Aufruf nicht wieder greppen muss.
        // `vault_addr` ist die Bedingung: Ohne sie gibt es keinen eingerichteten
        // Agent, und ein leerer Eintrag wäre schlechter als keiner.
        if ($vomHost['vault_addr'] !== '') {
            self::schreiben($server, $vomHost);
        }

        return $vomHost;
    }

    /**
     * @param  array{vault_addr?: string, cns?: array<int, string>, hmac_kv_path?: string}  $werte
     */
    public static function schreiben(Server $server, array $werte): void
    {
        $bisher = $server->feature_data[self::SCHLUESSEL] ?? [];

        $server->jsonUpdate('feature_data', self::SCHLUESSEL, [
            'vault_addr'   => (string) ($werte['vault_addr'] ?? ($bisher['vault_addr'] ?? '')),
            'cns'          => array_values((array) ($werte['cns'] ?? ($bisher['cns'] ?? []))),
            'hmac_kv_path' => (string) ($werte['hmac_kv_path'] ?? ($bisher['hmac_kv_path'] ?? '')),
            'stand'        => now()->toIso8601String(),
        ]);
    }

    /** Beim Abbauen: die Zeile wegnehmen, nicht leeren. */
    public static function entfernen(Server $server): void
    {
        $server->jsonForget('feature_data', self::SCHLUESSEL);
    }

    /**
     * Der Rückfall: aus `agent.hcl` lesen.
     *
     * Bewusst an genau einer Stelle gebündelt. Vorher standen dieselben drei
     * Regexe doppelt — in `InstallAgent` und in `ManageCns` —, und zwei Kopien
     * einer Regex laufen irgendwann auseinander.
     *
     * @return array{vault_addr: string, cns: array<int, string>, hmac_kv_path: string}
     */
    private static function vomHost(Server $server): array
    {
        /** @var SSH $ssh */
        $ssh = $server->ssh();
        $hcl = self::AGENT_DIR.'/agent.hcl';

        return [
            'vault_addr' => trim($ssh->exec(
                "sudo grep -oP 'address\\s*=\\s*\"\\K[^\"]+' {$hcl} 2>/dev/null | head -n1 || true",
                'vault-mtls-read-addr',
            )),
            'cns' => array_values(array_filter(array_map(
                'trim',
                preg_split('/\R/', $ssh->exec(
                    "sudo grep -oP 'common_name=\\K[^\"]+' {$hcl} 2>/dev/null || true",
                    'vault-mtls-read-cns',
                )) ?: [],
            ))),
            'hmac_kv_path' => trim($ssh->exec(
                "sudo grep -oP '# Event-bus HMAC signing secret from Vault KV \\(\\K[^)]+' {$hcl} 2>/dev/null | head -n1 || true",
                'vault-mtls-read-hmac',
            )),
        ];
    }
}
