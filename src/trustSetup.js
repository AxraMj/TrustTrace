// For CLIs/demos only: create the verification authority. Agents never call this.
import { existsSync } from 'node:fs';
import { VerificationAuthority } from './trust/authority.js';

/** Uses secrets/verifier-private.pem if `npm run keygen` was run; otherwise an ephemeral in-memory key. */
export function loadAuthority() {
  if (existsSync('secrets/verifier-private.pem')) {
    return { authority: VerificationAuthority.fromKeyFile('secrets/verifier-private.pem'), source: 'secrets/verifier-private.pem' };
  }
  return { authority: VerificationAuthority.ephemeral(), source: 'ephemeral in-memory key (run `npm run keygen` for a persistent one)' };
}
