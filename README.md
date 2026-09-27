# provenance-middleware

One line that makes a service self-describing. It serves its own signed
[Provenance](https://github.com/provenance-protocol/provenance-protocol) declaration, proves on demand that it
holds the declared key, and reports which version is running.

```bash
npm install provenance-middleware
```

```js
import express from 'express';
import { provenance } from 'provenance-middleware';

const app = express();
app.use(provenance({ declaration: './PROVENANCE.yml' }));
```

That's it. Two addresses now exist:

| | |
|---|---|
| `GET /.well-known/provenance.json` | your signed declaration |
| `POST /.well-known/provenance/challenge` | proof that this service holds the declared key |
| `GET /.well-known/provenance/notices` | its recent signed notices |

Anyone can verify both **offline**, with no account and no call to any service —
including ours. See [provenance-protocol](https://github.com/provenance-protocol/provenance-protocol).

## Why not just commit a signed file?

Because a file drifts. Edit your declaration, forget to re-sign, and you are
publishing a signature that no longer matches — or worse, one that matches
something you changed weeks ago.

This signs **at startup**. Edit the declaration, restart, and the signature
covers what the file actually says. There is no state in which the two disagree.

And a file in a repository cannot prove that the service answering requests
right now holds the key. The challenge endpoint can.

## Setup

**Quickest:** in your project, run

```bash
npx provenance-protocol init --domain agent.example.com
```

It writes and signs `PROVENANCE.yml` from what your project already shows,
creates a key in `.provenance-key` (kept out of git), and asks only what it
cannot read. Set `PROVENANCE_PRIVATE_KEY` to that key in your service's
environment, add the line above, and you are done. The manual steps below do
the same by hand.

**1. Generate a keypair on your own machine.** The private half is used in your
process and never sent anywhere.

```bash
npx provenance-protocol keygen
```

Store the private key as `PROVENANCE_PRIVATE_KEY`. Never commit it.

**2. Write a declaration.** Minimum viable version:

```yaml
provenance: "0.2"
name: "Research Agent"
description: "Searches the web and summarises papers with citations."

provenance_id: "provenance:domain:agent.example.com"

capabilities:
  - read:web
  - write:summaries

constraints:            # public commitments — the most valuable field
  - no:pii
  - no:financial:transact

identity:
  public_key: "<the public key from step 1>"
  algorithm: ed25519
```

Note the identifier. **Use `provenance:domain:<your-hostname>`** when the service
serves its own declaration. A verifier confirms the declaration came from the
location its identifier names, and a hostname you control is that proof. Use a
repository identifier only if you also publish the declaration in that
repository — otherwise verifiers report `trustworthy: false`, because they cannot
confirm the file came from you. The middleware warns at startup if this is wrong.

**3. Mount it.** One line, as above.

## Other frameworks

The Express adapter is a thin wrapper. The core is a handler over standard
`Request`/`Response`, which returns `null` for paths it does not own:

```js
import { handler } from 'provenance-middleware';

const provenanceHandler = await handler({ declaration: './PROVENANCE.yml' });

// Next.js route handler, Hono, Fastify, Workers, Deno — anything fetch-shaped
export async function GET(request) {
  return (await provenanceHandler(request)) ?? new Response('Not found', { status: 404 });
}
```

Or sign without mounting anything:

```js
import { prepare } from 'provenance-middleware';
const { declaration, json } = await prepare({ declaration: './PROVENANCE.yml' });
```

## Options

| Option | |
|---|---|
| `declaration` | Path to a `.yml`/`.json` file, the document as a string, or a parsed object. Required. |
| `privateKey` | Base64 PKCS8 DER. Defaults to `PROVENANCE_PRIVATE_KEY`. |
| `version` | Overrides the declaration's `version` — handy for a build identifier. |
| `declarationPath` | Defaults to `/.well-known/provenance.json`. |
| `challengePath` | Defaults to `/.well-known/provenance/challenge`. |
| `noticesPath` | Defaults to `/.well-known/provenance/notices`. |
| `declarationUrl` | Public URL of the declaration, for the published notice. Defaults to the standard location for a domain id. |
| `notify` | HTTPS endpoints of watchers to send the published notice to. None by default. |
| `onNotify` | Called with each delivery outcome. |
| `notices` | Further signed notices to publish, e.g. incidents. |
| `deliverDeclaration` | Include the full signed declaration in the published notice, for internal services. |

## Notices — telling watchers what changed

On startup the middleware signs a **declaration-published** notice (which
declaration, by digest, and which version is running) and serves it with any
other notices you give it at:

| | |
|---|---|
| `GET /.well-known/provenance/notices` | your recent signed notices, newest first |

Anyone can read that without asking. To have watchers hear immediately rather
than on their next check, name them — your choice of attester, several, or none:

```js
app.use(provenance({
  declaration: './PROVENANCE.yml',
  notify: ['https://watcher.example/notices'],   // nothing is sent by default
}));
```

Delivery happens in the background; a watcher being down never delays or
breaks startup, and each failure is emitted as a warning (pass `onNotify` to
record outcomes). To disclose an incident, sign it with `signNotice` from
`provenance-protocol/keygen` and pass it in `notices`.

**Internal services.** A service on a private network cannot be fetched by an
outside watcher, so let it hand the declaration over instead:

```js
app.use(provenance({
  declaration: './PROVENANCE.yml',
  deliverDeclaration: true,                     // the full signed declaration travels in the notice
  notify: ['https://watcher.example/notices'],
}));
```

Your organisation then vouches for the agent with
`npx provenance-protocol affiliate` — see provenance-protocol, *Internal agents*.
The watcher never needs access to your network.

## What it does not do

**It never sends your private key anywhere.** Signing happens in your process.

**It reports nothing about your traffic, users or requests.** The only thing
published is your declaration and version — the things you wrote down yourself.
This is not analytics.

**It never signs the legacy challenge payload.** Spec 0.1 signed a challenge as
`<provenance_id>:<nonce>` and a revocation as `<provenance_id>:REVOKE` — the same
string with a chosen nonce. An endpoint signing that form would let any stranger
obtain a valid revocation for your key and revoke you. This only ever signs the
domain-separated form, so no nonce can be turned into a revocation.

**It does not validate that your declaration is true.** It publishes what you
wrote and proves you wrote it. Whether your agent honours its constraints is not
something a signature can establish.

## Verifying it worked

```js
import { verifyDeclaration } from 'provenance-protocol/verify';

const url = 'https://agent.example.com/.well-known/provenance.json';
const result = await verifyDeclaration(await (await fetch(url)).json(), { retrievedFrom: url });

result.valid        // the signature checks out against the key in the file
result.coverage     // 'declaration' — every field is covered
result.location     // 'match' — served from the location its identifier names
result.trustworthy  // both of the above
```

All four should be as shown. If `location` is `unchecked`, your identifier does
not name this host — see step 2.

## License

Apache License 2.0 — see [LICENSE](./LICENSE). Versions before 0.3.2 were released under MIT.
