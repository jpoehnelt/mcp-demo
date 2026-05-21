// Discovery + JWKS endpoints.
//
// Spec anchors:
//   - specs/authorization-server.md §1 (endpoint list)
//   - specs/authorization-server.md §3.1 (RFC 8414 AS metadata)
//   - specs/authorization-server.md §3.2 (OIDC Discovery mirror)
//   - specs/authorization-server.md §3.3 + §6 (JWKS + key management)
//
// All three responses MUST advertise `Cache-Control: max-age=3600` (§3.3 and
// the §3.1/§3.2 acceptance criteria). The `alg` value surfaced in the OIDC
// mirror and JWKS is derived at runtime from the active signing keyset —
// hardcoding `RS256` would silently lie to clients when an operator boots
// with `AS_SIGNING_ALG=ES256` or `EdDSA`.
//
// Deps are passed explicitly (`env`, `keys`) rather than pulled off
// `c.var` so the registration helper is a pure function of its inputs and
// callers can compose it without binding the whole `IdPVariables` shape.

import type { IdPApp } from "../app.js";
import type { IdPEnv } from "../env.js";
import type { SigningKeyset } from "../keys.js";

interface RegisterDeps {
  env: IdPEnv;
  keys: SigningKeyset;
}

const CACHE_CONTROL = "max-age=3600";

/**
 * AS metadata payload per §3.1. The shape is frozen by the spec — fields
 * are listed in the order the spec uses to make a diff-against-spec read
 * trivial.
 */
interface AsMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  response_types_supported: readonly ["code"];
  grant_types_supported: readonly ["authorization_code", "refresh_token"];
  code_challenge_methods_supported: readonly ["S256"];
  token_endpoint_auth_methods_supported: readonly ["none"];
  client_id_metadata_document_supported: true;
  scopes_supported: readonly ["weather:read", "weather:premium"];
}

/**
 * OIDC mirror payload per §3.2 — AS metadata plus three OIDC-specific
 * fields. `id_token_signing_alg_values_supported` reflects the active
 * `AS_SIGNING_ALG` (§3.2 acceptance criteria); `userinfo_endpoint` is
 * advertised so OIDC-aware discovery clients don't choke, even though this
 * PoC never issues an ID token (architecture §6 non-goal).
 */
interface OidcMetadata extends AsMetadata {
  subject_types_supported: readonly ["public"];
  id_token_signing_alg_values_supported: readonly [IdPEnv["AS_SIGNING_ALG"]];
  userinfo_endpoint: string;
}

function buildAsMetadata(env: IdPEnv): AsMetadata {
  const issuer = env.AS_ISSUER_URL;
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: true,
    // `openid` and `offline_access` are intentionally absent — see §3.1
    // closing note (no ID tokens; refresh issued unconditionally).
    scopes_supported: ["weather:read", "weather:premium"],
  };
}

function buildOidcMetadata(env: IdPEnv): OidcMetadata {
  return {
    ...buildAsMetadata(env),
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: [env.AS_SIGNING_ALG],
    userinfo_endpoint: `${env.AS_ISSUER_URL}/userinfo`,
  };
}

/**
 * Mount the three discovery endpoints + the userinfo stub on `app`.
 *
 * `userinfo` is a 200/`{}` stub because §3.2 advertises the endpoint and
 * we'd rather return an empty document than 404 an OIDC client. The spec
 * explicitly tells clients not to rely on it (OIDC is non-goal).
 */
export function registerMetadataRoutes(app: IdPApp, deps: RegisterDeps): void {
  const asMetadata = buildAsMetadata(deps.env);
  const oidcMetadata = buildOidcMetadata(deps.env);
  const jwks = { keys: [deps.keys.publicJwk] as const };

  app.get("/.well-known/oauth-authorization-server", (c) => {
    c.header("Cache-Control", CACHE_CONTROL);
    return c.json(asMetadata);
  });

  app.get("/.well-known/openid-configuration", (c) => {
    c.header("Cache-Control", CACHE_CONTROL);
    return c.json(oidcMetadata);
  });

  app.get("/jwks.json", (c) => {
    c.header("Cache-Control", CACHE_CONTROL);
    return c.json(jwks);
  });

  // §3.2 userinfo stub: 200 with `{}`. Returning a body (rather than 204)
  // keeps `Content-Type: application/json` honest, which is what OIDC
  // libraries probe for.
  app.get("/userinfo", (c) => c.json({}));
}
