/**
 * The CLI handles one MCP server per process. Only operator configuration may extend its
 * network authority, including fixed presets for known services; discovery and redirects never add trusted origins.
 */
import { getOpenApiMcpPreset } from './openapi-mcp-preset'

let policy:
  | {
      serverOrigin: string
      origins: Set<string>
      credentialOrigins: Set<string>
      issuer: string
      issuerSource: 'environment' | 'token-endpoint-origin' | 'server-origin' | 'openapi-mcp-preset'
    }
  | undefined

function parseUrl(value: string | URL): URL {
  const url = new URL(value)
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.hash || url.hostname.includes('*')) {
    throw new Error('Refusing an unsafe MCP/OAuth URL: require HTTP(S) without userinfo or fragments')
  }
  return url
}

export function configureNetworkPolicy(serverUrl: string, tokenEndpoint?: string): void {
  const server = parseUrl(serverUrl)
  const preset = getOpenApiMcpPreset(serverUrl, tokenEndpoint)
  const expectedIssuer =
    process.env.MCP_REMOTE_AUTH_ISSUER || preset?.issuer || (tokenEndpoint ? parseUrl(tokenEndpoint).origin : server.origin)
  const issuerSource = process.env.MCP_REMOTE_AUTH_ISSUER
    ? 'environment'
    : preset
      ? 'openapi-mcp-preset'
      : tokenEndpoint
        ? 'token-endpoint-origin'
        : 'server-origin'
  const issuer = parseUrl(expectedIssuer)
  if (issuer.search) throw new Error('MCP_REMOTE_AUTH_ISSUER must be an issuer URL without a query')
  const origins = new Set([server.origin, issuer.origin])
  const credentialOrigins = new Set([issuer.origin])
  // Exact origins only. No wildcard/suffix matching, and no paths that conceal a configuration error.
  const trustedOrigins = process.env.MCP_REMOTE_TRUSTED_ORIGINS ?? preset?.trustedOrigins.join(',') ?? ''
  for (const value of trustedOrigins.split(',').filter(Boolean)) {
    const url = parseUrl(value.trim())
    if (url.pathname !== '/' || url.search) throw new Error('MCP_REMOTE_TRUSTED_ORIGINS must contain exact origins')
    origins.add(url.origin)
    credentialOrigins.add(url.origin)
  }
  if (tokenEndpoint) origins.add(parseUrl(tokenEndpoint).origin)
  policy = { serverOrigin: server.origin, origins, credentialOrigins, issuer: expectedIssuer, issuerSource }
}

export function assertAllowedUrl(value: string | URL): void {
  const url = parseUrl(value)
  if (!policy) return // Standalone helpers have no CLI configuration; both CLI entry points initialize it before I/O.
  if (!policy.origins.has(url.origin)) {
    throw new Error(`Untrusted MCP/OAuth origin ${url.origin}; configure MCP_REMOTE_AUTH_ISSUER or MCP_REMOTE_TRUSTED_ORIGINS explicitly`)
  }
  // HTTP is allowed only for the explicitly configured MCP origin (e.g. --allow-http/local development).
  if (url.protocol !== 'https:' && url.origin !== policy.serverOrigin) {
    throw new Error('Discovered OAuth endpoints must use HTTPS')
  }
}

export function assertExpectedIssuer(issuer: string): void {
  assertAllowedUrl(issuer)
  if (policy && issuer.replace(/\/$/, '') !== policy.issuer.replace(/\/$/, '')) {
    const source =
      policy.issuerSource === 'environment'
        ? 'Expected issuer source: MCP_REMOTE_AUTH_ISSUER (explicit configuration).'
        : policy.issuerSource === 'openapi-mcp-preset'
          ? 'Expected issuer source: built-in Alibaba Cloud OpenAPI MCP preset (full tenant URL).'
          : policy.issuerSource === 'token-endpoint-origin'
            ? 'Expected issuer source: --token-endpoint origin (default); MCP_REMOTE_AUTH_ISSUER is not set.'
            : 'Expected issuer source: MCP server origin (default); MCP_REMOTE_AUTH_ISSUER is not set.'
    // Do not echo issuer URLs: their paths can contain private tenant identifiers.
    throw new Error(
      [
        'OAuth issuer differs from the expected issuer; refusing to release credentials.',
        source,
        'This service may use a path-scoped or separate authorization issuer.',
        'Set MCP_REMOTE_AUTH_ISSUER to the exact issuer confirmed by the service operator, including any path.',
        'Do not copy an unexpected discovered issuer merely to silence this error.',
      ].join('\n'),
    )
  }
}

/** Used before obtaining a token, so no bearer credential can reach another SSE origin. */
export function assertResourceOrigin(value: string | URL, serverUrl: string | URL): void {
  if (parseUrl(value).origin !== parseUrl(serverUrl).origin) throw new Error('Refusing to send MCP credentials across origins')
}

/** Discovery and grants do not follow redirects. SDK transports may explicitly follow same-origin redirects. */
export async function guardedFetch(input: string | URL, init?: RequestInit): Promise<Response> {
  assertAllowedUrl(input)
  return fetch(input, { ...init, redirect: 'manual' })
}

/** Authorization metadata cannot turn the MCP origin into the recipient of another issuer's secrets. */
export function assertAuthorizationMetadata(metadata: { issuer: string; [key: string]: unknown }): void {
  assertExpectedIssuer(metadata.issuer)
  for (const key of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'device_authorization_endpoint']) {
    const endpoint = metadata[key]
    if (typeof endpoint !== 'string') continue
    assertAllowedUrl(endpoint)
    if (policy && !policy.credentialOrigins.has(parseUrl(endpoint).origin)) {
      throw new Error('OAuth endpoint is outside the configured authorization server origins')
    }
  }
}

export function configuredIssuer(): string | undefined {
  return policy?.issuer
}
