import { handler, INDEX_PATH } from '../src/index.js';
import { generateProvenanceKeyPair } from 'provenance-protocol/keygen';
import { readIndex } from 'provenance-protocol';
import { validateIndex } from 'provenance-protocol/validate';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); ok ? pass++ : fail++; };
const k = generateProvenanceKeyPair();
const declaration = { provenance: '0.2', name: 'Support Agent', description: 'Answers support questions.', provenance_id: 'provenance:domain:example.com/agents/support',
  identity: { public_key: k.publicKey, algorithm: 'ed25519' } };

const h = await handler({ declaration, privateKey: k.privateKey, declarationPath: '/agents/support/.well-known/provenance.json',
  index: { operator: 'provenance:domain:example.com', agents: [{ provenance_id: 'provenance:github:example/research-agent', name: 'Research Agent' }] } });
const url = `https://example.com${INDEX_PATH}`;
const res = await h(new Request(url));
const body = await res.json();
t('the index is served at its fixed address', res.status === 200);
t('it is valid', validateIndex(body).valid, JSON.stringify(validateIndex(body).errors));
const r = readIndex(body, { fetchedFrom: url });
t('it lists this service and the others, and reads back for this host', r.valid && r.agents.length === 2 && r.agents[0].provenanceId === declaration.provenance_id, JSON.stringify(r));
t('the site is the host it is served from', body.site === 'example.com');
const plain = await handler({ declaration, privateKey: k.privateKey });
t('without the option no index is served', (await plain(new Request(url))) === null);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
