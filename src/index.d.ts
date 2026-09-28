/**
 * provenance-middleware — TypeScript definitions
 *
 * Makes a service self-describing: serves its own signed declaration, proves it
 * holds the declared key, and reports which version is running.
 */

/** Where the declaration is served from. */
export const DECLARATION_PATH: '/.well-known/provenance.json';
/** Where key-control challenges are answered. */
export const CHALLENGE_PATH: '/.well-known/provenance/challenge';
/** Where recent signed notices are published, newest first. */
export const NOTICES_PATH: '/.well-known/provenance/notices';

export class ProvenanceMiddlewareError extends Error {
  name: 'ProvenanceMiddlewareError';
}

export interface ProvenanceOptions {
  /**
   * The declaration: a path to a .yml/.yaml/.json file, the document as a
   * string, or an already-parsed object. It must declare `provenance: "0.2"`,
   * a `provenance_id`, and `identity.public_key`.
   */
  declaration: string | object;
  /**
   * Base64 PKCS8 DER private key. Defaults to `PROVENANCE_PRIVATE_KEY`.
   * Generate it on your own machine; it is used in this process and never sent
   * anywhere.
   */
  privateKey?: string;
  /** Overrides the declaration's `version` — useful for a build identifier. */
  version?: string;
  /** Defaults to `/.well-known/provenance.json`. */
  declarationPath?: string;
  /** Defaults to `/.well-known/provenance/challenge`. */
  challengePath?: string;
  /** Defaults to `/.well-known/provenance/notices`. */
  noticesPath?: string;
  /** Public URL of the served declaration. Defaults to the standard location for a domain id. */
  declarationUrl?: string;
  /** Further notices you signed (e.g. incidents), published alongside. Kept in memory. */
  notices?: object[];
  /**
   * Include the full signed declaration in the published notice — for internal
   * or private services that watchers cannot fetch. Pair with `notify`.
   */
  deliverDeclaration?: boolean;
  /**
   * Report which version of each declared npm dependency this running service
   * actually has installed (from package-lock.json, or the path given), for
   * comparison with the declaration's pins (spec 0.3). Only declared
   * dependencies are reported.
   */
  reportResolved?: boolean | string;
  /**
   * Watchers to send the signed "declaration published" notice to at startup —
   * any attester, several, or none. Nothing is sent by default.
   */
  notify?: string[];
  /** Called with the outcome of each delivery. Failures are also emitted as warnings. */
  onNotify?: (result: NotifyResult) => void;
}

export interface NotifyResult {
  url: string;
  ok: boolean;
  status?: number;
  error?: string;
}

export interface PreparedDeclaration {
  /** The declaration as served, with a freshly computed signature. */
  declaration: object;
  provenanceId: string;
  publicKey: string;
  /** The serialised body served at the declaration path. */
  json: string;
  /** Signed declaration-published notice, or null when no URL could be determined. */
  published: object | null;
  /** Everything served at the notices path. */
  notices: object[];
}

/** POST a signed notice to each watcher. Never throws; failures are warned and returned. */
export function sendNotice(
  notice: object, urls: string[], onNotify?: (result: NotifyResult) => void
): Promise<NotifyResult[]>;

/**
 * Read and sign the declaration without mounting anything.
 *
 * Signing happens at load, so there is no state in which the file says one
 * thing and the signature covers another.
 */
export function prepare(options: ProvenanceOptions): Promise<PreparedDeclaration>;

/**
 * Framework-agnostic handler over web-standard Request/Response.
 *
 * Returns a Response for the two paths it owns and `null` for anything else, so
 * it composes with any router — Next.js route handlers, Hono, Fastify, Workers,
 * Deno.
 */
export function handler(
  options: ProvenanceOptions
): Promise<(request: Request) => Promise<Response | null>>;

/**
 * Express / Connect middleware.
 *
 * ```js
 * app.use(provenance({ declaration: './PROVENANCE.yml' }));
 * ```
 */
export function provenance(
  options: ProvenanceOptions
): (req: unknown, res: unknown, next: (err?: unknown) => void) => void;
