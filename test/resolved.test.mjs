import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { prepare } from '../src/index.js';
import { verifyNotice, checkPins } from 'provenance-protocol';
import { validateNotice } from 'provenance-protocol/validate';
import { generateProvenanceKeyPair } from 'provenance-protocol/keygen';

let pass = 0, fail = 0;
const t = (name, ok, d = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + d}`); ok ? pass++ : fail++; };

const k = generateProvenanceKeyPair();
const dir = mkdtempSync(join(tmpdir(), 'mw-res-'));
const lock = join(dir, 'package-lock.json');
writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: {
  '': { name: 'svc' },
  'node_modules/postmark-mcp': { version: '1.0.16', integrity: 'sha512-AAAA' },
  'node_modules/left-pad': { version: '1.3.0' },
} }));
const declaration = { provenance: '0.3', name: 'Mailer', description: 'Sends receipts.', provenance_id: 'provenance:domain:mail.example.com',
  dependencies: [{ kind: 'mcp_server', url: 'https://www.npmjs.com/package/postmark-mcp', pin: { version: '1.0.15' } }],
  identity: { public_key: k.publicKey, algorithm: 'ed25519' } };

const p = await prepare({ declaration, privateKey: k.privateKey, reportResolved: lock });
const n = p.published;
t('a 0.3 declaration is served as 0.3', p.declaration.provenance === '0.3');
t('the notice reports what is installed, as format 0.2', n.notice === '0.2' && n.claims.resolved?.[0]?.version === '1.0.16', JSON.stringify(n.claims.resolved));
t('only declared dependencies are reported', n.claims.resolved.length === 1);
t('the notice is valid and verifies', validateNotice(n).valid && (await verifyNotice(n, { publicKey: k.publicKey })).valid, JSON.stringify(validateNotice(n).errors));
t('and a watcher sees the pin was not honoured', checkPins(p.declaration, n)[0].result === 'mismatch');
const plain = await prepare({ declaration, privateKey: k.privateKey });
t('without the option nothing is reported and the notice stays 0.1', plain.published.notice === '0.1' && !plain.published.claims.resolved);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
