import { handler, provenance } from '../src/index.js';
import { generateProvenanceKeyPair } from 'provenance-protocol/keygen';
import { verifyNotice } from 'provenance-protocol/verify';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); ok ? pass++ : fail++; };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Watchers must be https; stand in for them by recording what would be posted.
const posted = [];
let answer = 200;
globalThis.fetch = async (url, init) => { posted.push({ url: String(url), notice: JSON.parse(init.body) }); return new Response('{}', { status: answer }); };
process.env.PROVENANCE_TEST_MIN_INTERVAL = '150';

const k = generateProvenanceKeyPair();
const declaration = { provenance: '0.2', name: 'HR Assistant', description: 'Answers staff questions.', provenance_id: 'provenance:domain:hr.corp.internal',
  identity: { public_key: k.publicKey, algorithm: 'ed25519' } };
const results = [];
const h = await handler({ declaration, privateKey: k.privateKey, deliverDeclaration: true, notify: ['https://watcher.example/notices'], renewEvery: 150, onNotify: (r) => results.push(r) });
await wait(500);
h.stop();
const n = posted.length;
t('the start-up notice and renewals arrive', n >= 3, String(n));
const [first, second] = posted.map((p) => p.notice);
t('a renewal has a new id', second.id !== first.id);
t('and a later or equal issued_at', second.issued_at >= first.issued_at);
t('it verifies against the declaration key', (await verifyNotice(second, { publicKey: k.publicKey })).valid);
t('it names the same declaration', second.claims.declaration_digest === first.claims.declaration_digest);
t('it still carries the declaration', !!second.claims.declaration && second.claims.declaration.identity.signature === first.claims.declaration.identity.signature);
t('each delivery is reported', results.length === n);
const res = await h(new Request('https://hr.corp.internal/.well-known/provenance/notices'));
const feed = await res.json();
t('the feed holds the latest renewal and the start-up notice, not every renewal', feed.length === 2 && feed[1].id === first.id, String(feed.length));
await wait(400);
t('stop() stops further deliveries', posted.length === n);

// A failing watcher is reported, never thrown.
answer = 500; posted.length = 0; results.length = 0;
const warned = []; const onWarn = (w) => warned.push(w.message); process.on('warning', onWarn);
const h2 = await handler({ declaration, privateKey: k.privateKey, notify: ['https://watcher.example/notices'], renewEvery: 150, onNotify: (r) => results.push(r) });
await wait(400);
h2.stop(); await wait(50); process.off('warning', onWarn);
t('a watcher answering 500 is reported through onNotify', results.length >= 2 && results.every((r) => !r.ok && r.status === 500));
t('and warned about, without throwing', warned.some((w) => /500/.test(w)));

// Off when asked; raised to the minimum when too small.
posted.length = 0; answer = 200;
const h3 = await handler({ declaration, privateKey: k.privateKey, notify: ['https://watcher.example/notices'], renewEvery: false });
await wait(400); h3.stop();
t('renewEvery: false sends only the start-up notice', posted.length === 1, String(posted.length));
const w2 = []; const onWarn2 = (w) => w2.push(w.message); process.on('warning', onWarn2);
const h4 = await handler({ declaration, privateKey: k.privateKey, notify: ['https://watcher.example/notices'], renewEvery: 10 });
h4.stop(); await wait(50); process.off('warning', onWarn2);
t('an interval below the minimum is raised, with a warning', w2.some((w) => /below the minimum/.test(w)));
posted.length = 0;
const h5 = await handler({ declaration, privateKey: k.privateKey });
await wait(300); h5.stop();
t('with no watchers nothing is sent and nothing renews', posted.length === 0);
const mw = provenance({ declaration, privateKey: k.privateKey, notify: ['https://watcher.example/notices'], renewEvery: 150 });
await mw.stop();
t('the middleware exposes stop() as well', typeof mw.stop === 'function');

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
