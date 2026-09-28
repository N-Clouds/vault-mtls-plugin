<?php

declare(strict_types=1);

use Illuminate\Support\Facades\View;

/**
 * Die gerenderten Agent-Skripte — HA-Tauglichkeit und Rechte.
 *
 * ## Warum die Vorlagen direkt geprüft werden
 *
 * `SSHFake` merkt sich nur den **letzten** Upload (`$uploadedContent` ist ein
 * einzelner String). `InstallAgent` schreibt aber fünf Dateien; über den Handler
 * käme man an `agent.hcl` also nicht heran. Die Vorlagen sind ohnehin der Ort,
 * an dem die Entscheidungen stehen — hier geprüft, ohne SSH und ohne Server.
 *
 * ## Was hier scharf ist
 *
 * Alle drei HA-Einstellungen und die Rechte-Korrekturen sind am 28.09.2026
 * entstanden und noch **nie ausgeführt** worden. Fällt eine davon bei einer
 * späteren Änderung weg, merkt es sonst niemand:
 *
 *   * ohne `retry` **endet der Agent** bei einer Leader-Wahl — die Zertifikate
 *     laufen aus und `eventbus-hmac` wird nicht mehr erneuert, auffallen würde es
 *     Tage später;
 *   * ohne `install -m` liegt das HMAC-Geheimnis zwischen `cp` und `chmod` mit
 *     der Umask der Wurzel da, also world-readable — bei **jeder** Rotation neu.
 */
uses(Tests\TestCase::class);

beforeEach(function () {
    // Was `PluginsServiceProvider` über RegisterViews tut. Beim direkten
    // `(new Plugin)->boot()` im Test läuft `loadViewsFrom` nicht mehr mit.
    View::addNamespace('vault-mtls', __DIR__.'/../views');
});

function agentHcl(array $ueberschreiben = []): string
{
    return view('vault-mtls::scripts.agent-hcl', array_merge([
        'vaultAddr' => 'https://vault.n-clouds.local:8200',
        'agentDir' => '/etc/vault-agent',
        'mtlsDir' => '/etc/nginx/mtls',
        'tokenDir' => '/run/vault-agent',
        'hmacKvPath' => 'secret/data/eventbus/hmac',
        'ldelim' => '{{',
        'rdelim' => '}}',
        'cns' => [
            ['cn' => 'cms.services.n-clouds.local', 'short' => 'cms', 'home' => '/home/cms'],
            ['cn' => 'central.services.n-clouds.local', 'short' => 'central', 'home' => '/home/central'],
        ],
    ], $ueberschreiben))->render();
}

// ── HA ──────────────────────────────────────────────────────────────────────

it('haelt eine Leader-Wahl aus', function () {
    $hcl = agentHcl();

    expect($hcl)
        // Ohne Wiederholung endet der Agent, wenn der Cluster kurz nicht
        // schreibfaehig ist. Ausdruecklich gesetzt, nicht auf die Vorgabe vertraut.
        ->toContain('retry {')
        ->toContain('num_retries')
        // Ein fehlgeschlagenes Rendern ist im HA-Betrieb normal und kein Grund,
        // den Dienst zu verlassen — sonst waere der geholte Token weg.
        ->toContain('exit_on_retry_failure = false')
        // Startet der Agent mitten in einer Wahl, soll er warten statt aufzugeben.
        ->toContain('min_backoff')
        ->toContain('max_backoff');
});

it('nennt genau eine Adresse, und zwar die uebergebene', function () {
    /*
     * Der Vault-Agent kennt nur EINE `address`. Zusaetzlich haengt daran der
     * Zustands-Rueckfall: `Zustand::vomHost()` liest sie mit
     * `grep -oP 'address\s*=\s*"\K[^"]+' … | head -n1` zurueck. Stuende irgendwo
     * darueber eine zweite Fundstelle — auch in einem Kommentar —, laege der
     * Rueckfall falsch.
     */
    $hcl = agentHcl(['vaultAddr' => 'https://vault-ha.n-clouds.local:8200']);

    preg_match_all('/address\s*=\s*"([^"]+)"/', $hcl, $treffer);

    expect($treffer[1])->toHaveCount(1)
        ->and($treffer[1][0])->toBe('https://vault-ha.n-clouds.local:8200');
});

// ── Vorlagen je CN ──────────────────────────────────────────────────────────

it('erzeugt je CN einen Zertifikatsblock', function () {
    $hcl = agentHcl();

    expect(substr_count($hcl, 'common_name='))->toBe(2)
        ->and($hcl)->toContain('common_name=cms.services.n-clouds.local')
        ->and($hcl)->toContain('common_name=central.services.n-clouds.local')
        ->and($hcl)->toContain('destination = "/etc/nginx/mtls/cms.pem"')
        // Nur der Eigentuemer darf lesen — der private Schluessel steckt darin.
        ->and($hcl)->toContain('perms       = "0640"');
});

it('laesst die Go-Vorlagen-Klammern unversehrt durch Blade', function () {
    // `{{ }}` ist Blades eigene Syntax. Ohne `{!! $ldelim !!}` wuerde Blade die
    // Go-Vorlagen des Agents auswerten oder maskieren — der Agent bekaeme dann
    // Unsinn und renderte nichts.
    $hcl = agentHcl();

    expect($hcl)->toContain('{{ with secret "pki_int/issue/service"')
        ->and($hcl)->toContain('{{ .Data.certificate }}')
        ->and($hcl)->not->toContain('&quot;')
        ->and($hcl)->not->toContain('&#');
});

it('rendert den HMAC-Block nur, wenn ein KV-Pfad gesetzt ist', function () {
    /*
     | Geprueft wird die ZIELZEILE, nicht das Wort.
     |
     | Der Kopfkommentar zur HA-Haertung erwaehnt `eventbus-hmac` im Text; nur
     | `destination = …/eventbus-hmac` steht ausschliesslich im bedingten Block.
     */
    expect(agentHcl())->toContain('destination = "/etc/nginx/mtls/eventbus-hmac"')
        ->and(agentHcl(['hmacKvPath' => '']))
        ->not->toContain('destination = "/etc/nginx/mtls/eventbus-hmac"');
});

it('behaelt den Kommentar-Anker, aus dem der KV-Pfad zurueckgelesen wird', function () {
    /*
     * `Zustand::vomHost()` greppt diesen Kommentar als Rueckfall fuer Hosts, die
     * vor 09/2026 eingerichtet wurden. Wer ihn umformuliert, nimmt solchen Hosts
     * beim naechsten "Manage service names" den KV-Pfad weg — die HMAC-Vorlage
     * verschwindet, das Geheimnis wird nicht mehr erneuert, und es faellt erst bei
     * der naechsten Rotation auf.
     */
    expect(agentHcl())->toContain('# Event-bus HMAC signing secret from Vault KV (secret/data/eventbus/hmac)');
});

// ── Rechte ──────────────────────────────────────────────────────────────────

it('setzt die Rechte beim Anlegen, nicht danach', function () {
    /*
     * DER Sicherheitstest dieser Datei.
     *
     * `cp` + `chmod` hinterlaesst ein Fenster, in dem die Datei mit der Umask der
     * Wurzel dasteht — meist 0644, also fuer jeden lokalen Benutzer lesbar. Beim
     * HMAC-Geheimnis der Plattform ist das genau die Bedrohung, gegen die mTLS
     * ueberhaupt existiert: andere App-Benutzer auf demselben Host. Und es
     * wiederholt sich bei JEDER Rotation.
     */
    $skript = view('vault-mtls::scripts.sync-home-certs', [
        'mtlsDir' => '/etc/nginx/mtls',
        'agentDir' => '/etc/vault-agent',
        'cns' => [['cn' => 'cms.services.n-clouds.local', 'short' => 'cms', 'home' => '/home/cms']],
    ])->render();

    expect($skript)
        ->toContain('install -m 0640 -o "$short" "$MTLS_DIR/eventbus-hmac"')
        ->toContain('install -m 0640 -o "$short" "$MTLS_DIR/$short.pem"')
        ->toContain('install -d -m 0750 -o "$short"')
        // Kein cp mehr auf die geheimen Dateien.
        ->not->toContain('cp -f "$MTLS_DIR/eventbus-hmac"')
        ->not->toContain('cp -f "$MTLS_DIR/$short.pem"');
});

it('legt das Zertifikatsverzeichnis nicht world-listable an', function () {
    // Die Dateien darin sind je Datei geschuetzt, das VERZEICHNIS blieb aber auf
    // der Umask-Vorgabe — jeder lokale Benutzer konnte auflisten, welche
    // Dienst-CNs es auf dem Host gibt.
    $skript = view('vault-mtls::scripts.install-agent', [
        'agentDir' => '/etc/vault-agent',
        'mtlsDir' => '/etc/nginx/mtls',
        'tokenDir' => '/run/vault-agent',
    ])->render();

    expect($skript)->toContain('chmod 750 /etc/nginx/mtls')
        ->toContain('chmod 700 /etc/vault-agent')
        // Ohne diesen Eintrag stirbt der Agent nach jedem Reboot: /run ist tmpfs,
        // die Token-Senke ist weg, Supervisor gibt auf, und die 72h-Zertifikate
        // laufen ab.
        ->toContain('/etc/tmpfiles.d/vault-agent.conf');
});

it('laesst gpg nicht nachfragen', function () {
    /*
     * Ohne `--batch --yes` fragt gpg "File exists. Overwrite?", wenn der
     * Schluesselbund schon liegt — ohne Terminal scheitert das und `set -e` bricht
     * ab. Die Wache prueft die BINAERDATEI, der Seiteneffekt ist aber der
     * Schluesselbund: Ein Lauf, der ihn schreibt und dann bei `apt-get install`
     * scheitert, haengt bei jedem weiteren Versuch an dieser Stelle.
     */
    $skript = view('vault-mtls::scripts.install-vault', [])->render();

    expect($skript)->toContain('gpg --batch --yes --dearmor')
        // Der gebuendelte Vault-SERVER darf nicht laufen; wir fahren nur den Agent.
        ->toContain('systemctl disable --now vault');
});
