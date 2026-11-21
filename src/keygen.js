// Generate the verification authority's Ed25519 key pair: npm run keygen [-- --force]
//   secrets/verifier-private.pem  -> ONLY the verification authority reads this (gitignored)
//   config/trust-anchor.pem       -> public key for Agent B (safe to share)
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { generateTrustKeys } from './trust/authority.js';

const PRIVATE = 'secrets/verifier-private.pem';
const PUBLIC = 'config/trust-anchor.pem';
if ((existsSync(PRIVATE) || existsSync(PUBLIC)) && !process.argv.includes('--force')) {
  console.error('Keys already exist. Re-run with --force to replace them (all previously signed evidence becomes untrusted).');
  process.exit(1);
}
const { privateKeyPem, publicKeyPem } = generateTrustKeys();
mkdirSync('secrets', { recursive: true });
mkdirSync('config', { recursive: true });
writeFileSync(PRIVATE, privateKeyPem, { mode: 0o600 });
writeFileSync(PUBLIC, publicKeyPem);
console.log(`Wrote ${PRIVATE} (keep secret; gitignored) and ${PUBLIC} (public).`);
