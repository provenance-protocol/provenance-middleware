/**
 * provenance-middleware
 *
 * One line that makes a service self-describing:
 *
 *   import { provenance } from 'provenance-middleware';
 *   app.use(provenance({ declaration: './PROVENANCE.yml' }));
 *
 * From then on the service serves its own signed declaration, proves on demand
 * that it holds the declared key, and reports which version is running. Nobody
 * has to remember to re-sign a file or keep a copy in a repository up to date —
 * the running service is the publication point.
 *
 * Three things it does NOT do, on purpose:
 *
 *   - It never sends the private key anywhere. Signing happens in this process.
 *   - It never signs a caller-supplied value in the legacy 0.1 challenge form.
 *     That payload is indistinguishable from a revocation, so an endpoint using
 *     it would let a stranger revoke the key. Only the domain-separated form is
 *     ever signed. See provenance-protocol SPEC.md § Signing and Verification.
 *   - It does not report anything about your traffic, users or requests. The
 *     only thing it ever sends is a signed notice that this declaration is
 *     published — and only to watchers you list in `notify`.
 */

import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { signDeclaration, signAgentChallenge, signNotice } from 'provenance-protocol/keygen';
import { declarationDigest, keyFingerprint, locateDeclaration } from 'provenance-protocol/verify';

/** Where a declaration is served from. Same shape as robots.txt: a fixed path. */
export const DECLARATION_PATH = '/.well-known/provenance.json';
/** Where key-control challenges are answered. */
export const CHALLENGE_PATH = '/.well-known/provenance/challenge';
/** Where this service's recent signed notices are published, newest first. */
export const NOTICES_PATH = '/.well-known/provenance/notices';

const NOTIFY_TIMEOUT_MS = 10000;

const MAX_NONCE_LENGTH = 256;
const NONCE_PATTERN = /^[A-Za-z0-9._~:-]+$/;

export class ProvenanceMiddlewareError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProvenanceMiddlewareError';
  }
}

function requirePrivateKey(privateKey) {
  const key = privateKey ?? process.env.PROVENANCE_PRIVATE_KEY;
  if (!key) {
    throw new ProvenanceMiddlewareError(
      'No private key. Set PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER, from `npx provenance-protocol keygen`) ' +
        'or pass privateKey. Generate it on your own machine — it must never reach a third party.'
    );
  }
  return key;
}

/**
 * Read a declaration from a file path, a string, or an already-parsed object.
 * YAML and JSON both work; the signature covers the parsed value, so formatting
 * and comments are irrelevant to it.
 */
async function loadDeclaration(declaration) {
  if (declaration === null || declaration === undefined) {
    throw new ProvenanceMiddlewareError('declaration is required (a path, a string, or a parsed object)');
  }
  if (typeof declaration === 'object') return declaration;
  if (typeof declaration !== 'string') {
    throw new ProvenanceMiddlewareError('declaration must be a path, a string, or a parsed object');
  }

  // A path if it looks like one; otherwise treat the string as the document.
  const looksLikePath = !declaration.includes('\n') && /\.(ya?ml|json)$/i.test(declaration.trim());
  const text = looksLikePath ? await readFile(declaration, 'utf8') : declaration;

  try {
    return parseYaml(text);
  } catch (e) {
    throw new ProvenanceMiddlewareError(`Declaration could not be parsed: ${e.message}`);
  }
}

/**
 * Prepare the signed declaration this service will serve.
 *
 * Signing happens here, at startup, rather than being something a developer
 * does by hand — which is the whole point. Edit the declaration, restart, and
 * the signature matches. There is no state in which the file says one thing and
 * the signature covers another.
 *
 * @param {object} options
 * @param {string|object} options.declaration  Path, document text, or parsed object
 * @param {string} [options.privateKey]        Defaults to PROVENANCE_PRIVATE_KEY
 * @param {string} [options.version]           Overrides the declaration's version
 * @param {string} [options.declarationUrl]    Public URL of the served declaration, for the
 *        published notice. Defaults to the standard location for a domain id.
 * @param {object[]} [options.notices]         Further signed notices to publish (e.g. incidents
 *        you signed with signNotice). Kept in memory; persist them yourself.
 * @param {boolean} [options.deliverDeclaration] Put the full signed declaration inside the
 *        published notice — for internal or private services that watchers cannot fetch.
 * @param {boolean|string} [options.reportResolved] Report, in the published notice, which
 *        version of each declared npm dependency this running service actually has installed
 *        (from package-lock.json, or the lockfile path given), so watchers can compare it with the
 *        declaration's pins. Only dependencies the declaration names are reported.
 * @returns {Promise<{ declaration: object, provenanceId: string, publicKey: string, json: string,
 *                     published: object, notices: object[] }>}
 */
export async function prepare({ declaration, privateKey, version, declarationUrl, notices = [], deliverDeclaration = false, reportResolved = false } = {}) {
  const key = requirePrivateKey(privateKey);
  const parsed = await loadDeclaration(declaration);

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ProvenanceMiddlewareError('Declaration must be a mapping');
  }

  const provenanceId = parsed.provenance_id;
  if (typeof provenanceId !== 'string' || provenanceId.length === 0) {
    throw new ProvenanceMiddlewareError(
      'Declaration needs provenance_id — it is what a verifier checks the retrieval location against'
    );
  }

  const identity = parsed.identity;
  const publicKey = identity && typeof identity === 'object' ? identity.public_key : undefined;
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    throw new ProvenanceMiddlewareError(
      'Declaration needs identity.public_key — the public half of the key this service signs with'
    );
  }

  // Spec 0.2 signs the whole declaration, so anything served must say 0.2.
  // Refuse to silently upgrade a file that claims 0.1: the author should know
  // their signature is about to cover every field rather than just the identity.
  if (parsed.provenance !== undefined && parsed.provenance !== '0.2' && parsed.provenance !== '0.3') {
    throw new ProvenanceMiddlewareError(
      `Declaration says provenance: "${parsed.provenance}". This middleware signs the whole declaration ` +
        '(spec 0.2 or 0.3). Set provenance: "0.2" — under 0.1 the signature would not cover your declared ' +
        'capabilities or constraints.'
    );
  }

  const body = { ...parsed, provenance: parsed.provenance ?? '0.2' };
  if (version) body.version = version;
  // The signature cannot cover itself, and a stale one must never be served.
  body.identity = { ...identity };
  delete body.identity.signature;
  body.identity.signature = signDeclaration(key, body);

  // A repo-shaped identifier on a service that serves its own declaration means
  // verifiers will report the retrieval location as 'unchecked', so nobody can
  // conclude the declaration is genuinely the operator's. Say so once, at
  // startup, rather than letting every vendor discover it from a silent
  // trustworthy: false.
  if (!provenanceId.startsWith('provenance:domain:')) {
    warn(
      `provenance_id is "${provenanceId}". Served from this service, a verifier cannot confirm that ` +
        'location, so it will report trustworthy: false. Either use provenance:domain:<your-hostname> ' +
        'or also publish this declaration at the location the id names.'
    );
  }

  // Announce what is being served. Signed, so it can travel by any route and
  // be pulled by anyone from the notices path without trusting the carrier.
  const digest = await declarationDigest(body);
  const url = declarationUrl ?? locateDeclaration(provenanceId);
  let published = null;
  const resolved = reportResolved ? resolvedFromLockfile(body, reportResolved === true ? 'package-lock.json' : reportResolved) : [];
  if (url) {
    const notice = {
      // Format 0.2 only when there is something it adds; 0.1 otherwise, for the widest readership.
      notice: resolved.length ? '0.2' : '0.1',
      id: `published-${digest.slice(7, 19)}-${Date.now().toString(36)}`,
      event: 'declaration-published',
      provenance_id: provenanceId,
      key_fingerprint: await keyFingerprint(publicKey),
      issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      claims: {
        declaration_url: url,
        declaration_digest: digest,
        ...(body.version ? { running_version: String(body.version) } : {}),
        // For a service nobody outside can reach, the watcher receives the
        // declaration itself rather than fetching it.
        ...(deliverDeclaration ? { declaration: body } : {}),
        ...(resolved.length ? { resolved } : {}),
      },
    };
    published = { ...notice, signature: signNotice(key, notice) };
  } else {
    warn('No declarationUrl and no standard location for this provenance_id, so no published notice is issued.');
  }

  if (!Array.isArray(notices)) throw new ProvenanceMiddlewareError('notices must be an array of signed notices');

  return {
    declaration: body,
    provenanceId,
    publicKey,
    json: `${JSON.stringify(body, null, 2)}\n`,
    published,
    notices: [published, ...notices].filter(Boolean),
  };
}

/**
 * Send the published notice to each watcher the operator chose. Runs in the
 * background: a watcher being down must never stop the service starting. Each
 * failure is reported as a warning — never swallowed — and every outcome is
 * passed to `onNotify` when given.
 *
 * @param {object} notice
 * @param {string[]} urls
 * @param {(result: { url: string, ok: boolean, status?: number, error?: string }) => void} [onNotify]
 */
export async function sendNotice(notice, urls, onNotify) {
  const results = await Promise.all(
    urls.map(async (url) => {
      try {
        const u = new URL(url);
        if (u.protocol !== 'https:') throw new Error('watcher URLs must be https');
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(notice),
          redirect: 'error',
          signal: AbortSignal.timeout(NOTIFY_TIMEOUT_MS),
        });
        return { url, ok: res.ok, status: res.status };
      } catch (e) {
        return { url, ok: false, error: e.message };
      }
    })
  );
  for (const r of results) {
    if (!r.ok) warn(`Could not notify ${r.url}: ${r.error ?? `HTTP ${r.status}`}`);
    try { onNotify?.(r); } catch { /* a callback must not take the service down */ }
  }
  return results;
}

/** Warnings go to stderr once and never throw — a log must not take a service down. */
function warn(message) {
  try {
    process.emitWarning(message, 'ProvenanceWarning');
  } catch {
    /* ignore */
  }
}

function json(status, value, extraHeaders = {}) {
  return new Response(`${JSON.stringify(value, null, 2)}\n`, {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

/**
 * The framework-agnostic core: a handler over web-standard Request/Response.
 *
 * Returns a Response for the two paths it owns and `null` for everything else,
 * so it composes with any router — Next.js route handlers, Hono, Fastify,
 * Cloudflare Workers, Deno.
 *
 * @param {object} options  Same as `prepare`, plus:
 * @param {string} [options.declarationPath]  Defaults to /.well-known/provenance.json
 * @param {string} [options.challengePath]    Defaults to /.well-known/provenance/challenge
 * @param {string} [options.noticesPath]      Defaults to /.well-known/provenance/notices
 * @param {string[]} [options.notify]         Watchers to send the published notice to at startup.
 *        Your choice — any attester, several, or none. Nothing is sent by default.
 * @param {Function} [options.onNotify]       Called with each delivery result
 * @returns {Promise<(request: Request) => Promise<Response|null>>}
 */
export async function handler(options = {}) {
  const {
    declarationPath = DECLARATION_PATH,
    challengePath = CHALLENGE_PATH,
    noticesPath = NOTICES_PATH,
    privateKey,
    notify = [],
    onNotify,
  } = options;

  const prepared = await prepare(options);
  const key = requirePrivateKey(privateKey);

  if (!Array.isArray(notify)) throw new ProvenanceMiddlewareError('notify must be an array of https URLs');
  if (notify.length && !prepared.published) {
    warn('notify is set but no published notice could be issued, so nothing was sent.');
  } else if (notify.length) {
    // Not awaited: start-up must not wait on, or fail because of, a watcher.
    sendNotice(prepared.published, notify, onNotify);
  }

  return async function provenanceHandler(request) {
    const { pathname } = new URL(request.url);

    if (pathname === declarationPath) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return json(405, { error: 'Method not allowed' }, { Allow: 'GET, HEAD' });
      }
      return new Response(request.method === 'HEAD' ? null : prepared.json, {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          // Anyone may verify a declaration, including from a browser page.
          'Access-Control-Allow-Origin': '*',
          // Short: a declaration changes when the service is redeployed, and a
          // verifier that caches a withdrawn one for a day is worse than one
          // that asks again.
          'Cache-Control': 'public, max-age=300',
        },
      });
    }

    if (pathname === noticesPath) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return json(405, { error: 'Method not allowed' }, { Allow: 'GET, HEAD' });
      }
      return new Response(request.method === 'HEAD' ? null : `${JSON.stringify(prepared.notices, null, 2)}\n`, {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=300',
        },
      });
    }

    if (pathname === challengePath) {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
          },
        });
      }
      if (request.method !== 'POST') {
        return json(405, { error: 'Method not allowed' }, { Allow: 'POST, OPTIONS' });
      }

      let nonce;
      try {
        const body = await request.json();
        nonce = body?.nonce;
      } catch {
        return json(400, { error: 'Body must be JSON: { "nonce": "..." }' });
      }

      // The signed payload is domain-separated, so no nonce can be turned into
      // a revocation or a declaration signature. These limits are belt and
      // braces: a bounded, predictable character set keeps the signed string
      // free of surprises and keeps the endpoint cheap to serve.
      if (typeof nonce !== 'string' || nonce.length === 0) {
        return json(400, { error: 'nonce is required' });
      }
      if (nonce.length > MAX_NONCE_LENGTH) {
        return json(400, { error: `nonce must be at most ${MAX_NONCE_LENGTH} characters` });
      }
      if (!NONCE_PATTERN.test(nonce)) {
        return json(400, { error: 'nonce must be unreserved URL characters only (A-Z a-z 0-9 . _ ~ : -)' });
      }

      return json(
        200,
        {
          provenance_id: prepared.provenanceId,
          public_key: prepared.publicKey,
          algorithm: 'ed25519',
          nonce,
          // Verify with verifyAgentChallenge() from provenance-protocol/verify.
          signature: signAgentChallenge(key, prepared.provenanceId, nonce),
          payload_domain: 'provenance-challenge-v1',
        },
        { 'Access-Control-Allow-Origin': '*' }
      );
    }

    return null;
  };
}

/**
 * Express / Connect middleware.
 *
 *   app.use(provenance({ declaration: './PROVENANCE.yml' }));
 *
 * Mounting is asynchronous underneath — the declaration has to be read and
 * signed — so requests arriving before that finishes wait rather than 404. If
 * preparation fails, every request to these paths reports why instead of
 * quietly serving nothing: a service that silently stops publishing its
 * declaration looks identical to one that never had it.
 *
 * @param {object} options  Same as `handler`
 * @returns {(req, res, next) => void}
 */
export function provenance(options = {}) {
  const ready = handler(options).then(
    (fn) => ({ fn, error: null }),
    (error) => ({ fn: null, error })
  );

  const paths = new Set([
    options.declarationPath ?? DECLARATION_PATH,
    options.challengePath ?? CHALLENGE_PATH,
    options.noticesPath ?? NOTICES_PATH,
  ]);

  return function provenanceMiddleware(req, res, next) {
    const pathname = (req.originalUrl ?? req.url ?? '').split('?')[0];
    if (!paths.has(pathname)) return next();

    ready
      .then(async ({ fn, error }) => {
        if (error) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.end(`${JSON.stringify({ error: 'Provenance declaration unavailable', reason: error.message }, null, 2)}\n`);
          return;
        }

        const host = req.headers?.host ?? 'localhost';
        const scheme = req.headers?.['x-forwarded-proto'] ?? (req.socket?.encrypted ? 'https' : 'http');
        const request = new Request(`${scheme}://${host}${pathname}`, {
          method: req.method,
          headers: new Headers(req.headers ?? {}),
          body: ['GET', 'HEAD'].includes(req.method) ? undefined : await readBody(req),
          duplex: 'half',
        });

        const response = await fn(request);
        if (!response) return next();

        res.statusCode = response.status;
        response.headers.forEach((value, name) => res.setHeader(name, value));
        res.end(response.body ? Buffer.from(await response.arrayBuffer()) : undefined);
      })
      .catch(next);
  };
}

function readBody(req) {
  if (req.body !== undefined) {
    return typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      // A challenge body is a short nonce. Nothing legitimate is large.
      if (size > 8192) {
        reject(new ProvenanceMiddlewareError('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const NPM_URL = /^https:\/\/www\.npmjs\.com\/package\/((?:@[^/]+\/)?[^/?#]+)/;

/**
 * What this running service actually has installed, for each npm dependency
 * the declaration names — read from the lockfile shipped with it. Nothing
 * beyond the declared dependencies is reported. A lockfile that cannot be read
 * is warned about, never silently treated as "nothing installed".
 */
function resolvedFromLockfile(declaration, lockfile) {
  const deps = Array.isArray(declaration.dependencies) ? declaration.dependencies : [];
  const wanted = deps.map((d) => [d, NPM_URL.exec(d?.url ?? '')?.[1]]).filter(([, name]) => name);
  if (!wanted.length) return [];
  let lock;
  try { lock = JSON.parse(readFileSync(resolve(process.cwd(), lockfile), 'utf8')); }
  catch (e) { warn(`reportResolved: could not read ${lockfile} (${e.message}); no resolved versions are reported.`); return []; }
  const out = [];
  for (const [d, name] of wanted) {
    const entry = lock.packages?.[`node_modules/${name}`] ?? lock.dependencies?.[name];
    if (!entry?.version) { warn(`reportResolved: ${name} is declared but not in ${lockfile}.`); continue; }
    out.push({ url: d.url, version: String(entry.version), ...(typeof entry.integrity === 'string' && /^sha(256|384|512)-/.test(entry.integrity) ? { integrity: entry.integrity } : {}) });
  }
  return out;
}
