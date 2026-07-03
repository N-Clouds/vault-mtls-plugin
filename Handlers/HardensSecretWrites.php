<?php

declare(strict_types=1);

namespace App\Vito\Plugins\NClouds\VaultMtlsPlugin\Handlers;

use App\Helpers\SSH;

/**
 * Mitigation for audit finding H2: Vito's SSH::write uploads the file content to a
 * world-readable /tmp intermediate (mode 0644) and never deletes it — leaving the plaintext
 * AppRole secret_id / role_id readable by ANY local user (incl. the /home/<app> service
 * accounts this system provisions). We cannot change Vito core, so immediately after writing
 * secrets we strip world-readability from the leftover temp.
 *
 * Matched narrowly to avoid touching anything else: /tmp TOP-LEVEL regular files, root-owned,
 * world-readable, whose name fits Vito's exact temp pattern — Str::random(10) followed by a
 * 10-digit unix timestamp. chmod (NOT delete) so even a false match is non-destructive. This
 * reduces the exposure from persistent-forever to the sub-second provisioning window.
 *
 * The fully clean fixes (a Vito-core patch to shred the temp, or an agent-unwrapped
 * response-wrapped secret_id so the value transiting /tmp is a spent single-use token) remain
 * follow-ups — this closes the persistent-leak without touching Vito or the Vault auth path.
 */
trait HardensSecretWrites
{
    protected function neutralizeSecretTemps(SSH $ssh): void
    {
        $ssh->exec(
            'sudo find /tmp -maxdepth 1 -type f -user root -perm -0004 '
            . "-regextype posix-extended -regex '.*/[A-Za-z0-9]{10}[0-9]{10}' "
            . '-exec chmod 600 {} + 2>/dev/null || true',
            'vault-mtls-neutralize-secret-temps'
        );
    }
}
