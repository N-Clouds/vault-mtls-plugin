<?php

use App\Models\Server;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers\ManageCns;
use App\Vito\Plugins\NClouds\VaultMtlsPlugin\Zustand;

/*
 * „Manage service names“ zeigt die bekannte CN-Liste vorbelegt an.
 *
 * Vorher war das Feld leer und ersetzte beim Absenden die ganze Liste: Wer eine App
 * ergaenzen wollte, musste alle anderen aus dem Gedaechtnis abtippen — ein vergessener
 * Name nahm dieser App beim naechsten Agent-Neustart das Zertifikat.
 */
uses(Tests\TestCase::class, Illuminate\Foundation\Testing\RefreshDatabase::class);

it('belegt die CN-Liste aus dem Zustand vor', function () {
    $server = Server::factory()->create();
    Zustand::schreiben($server, [
        'vault_addr' => 'https://vault1.n-clouds.local:8200',
        'cns' => ['central.services.n-clouds.local', 'spaces.services.n-clouds.local'],
        'hmac_kv_path' => 'secret/data/eventbus/hmac',
    ]);

    $form = (new ManageCns($server->fresh()))->form()?->toArray();
    $feld = collect($form['fields'] ?? $form)->firstWhere('name', 'app_cns');

    expect($feld)->not->toBeNull()
        ->and($feld['default'])->toBe("central.services.n-clouds.local\nspaces.services.n-clouds.local")
        ->and($feld['description'])->toContain('2 Name(n)');
});

it('bleibt ohne Zustand leer und sagt das', function () {
    $server = Server::factory()->create();

    $form = (new ManageCns($server))->form()?->toArray();
    $feld = collect($form['fields'] ?? $form)->firstWhere('name', 'app_cns');

    expect($feld['default'])->toBe('')
        ->and($feld['description'])->toContain('Noch keine Namen');
});
