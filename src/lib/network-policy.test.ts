import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createServer, type Server, type RequestListener } from 'node:http'
import { once } from 'node:events'
import open from 'open'
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from 'undici'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { writeJsonFile } from './mcp-auth-config'
import {
  assertAllowedUrl,
  assertAuthorizationMetadata,
  assertExpectedIssuer,
  assertResourceOrigin,
  configureNetworkPolicy,
  configuredIssuer,
  guardedFetch,
} from './network-policy'
import { discoverProtectedResourceMetadata } from './protected-resource-metadata'
import { fetchAuthorizationServerMetadata } from './authorization-server-metadata'
import { authorizeWithClientCredentials } from './client-credentials'
import { openBrowser } from './open-browser'
import { getServerUrlHash, fetchWithMcpHeaders, createResourceFetch } from './utils'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'

vi.mock('open', () => ({ default: vi.fn() }))

const servers: Server[] = []
let origin: string
let canary: string
let canaryHits: number
let mode: 'missing' | 'redirect' | 'metadata'

async function listen(handler: RequestListener): Promise<string> {
  const server = createServer(handler)
  servers.push(server)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`
}

beforeEach(async () => {
  vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', '')
  vi.stubEnv('MCP_REMOTE_TRUSTED_ORIGINS', '')
  canaryHits = 0
  mode = 'missing'
  canary = await listen((_req, res) => {
    canaryHits++
    res.end('{}')
  })
  origin = await listen((_req, res) => {
    if (mode === 'redirect') {
      res.writeHead(307, { location: `${canary}/stolen` }).end()
    } else if (mode === 'metadata') {
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ resource: `${origin}/mcp`, authorization_servers: [canary] }))
    } else {
      res.writeHead(404).end()
    }
  })
  configureNetworkPolicy(origin)
  vi.mocked(open).mockReset()
})

afterEach(async () => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  for (const server of servers.splice(0)) {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
})

describe('OAuth trust boundaries (local canaries only)', () => {
  it.each([
    ['cn-hangzhou', 'https://signin.aliyun.com', 'https://oauth.aliyun.com'],
    ['ap-southeast-1', 'https://signin.alibabacloud.com', 'https://oauth.alibabacloud.com'],
  ])('uses the fixed OpenAPI MCP preset for %s without environment configuration', (region, signin, oauth) => {
    delete process.env.MCP_REMOTE_AUTH_ISSUER
    delete process.env.MCP_REMOTE_TRUSTED_ORIGINS
    const issuer = `https://openapi-mcp.${region}.aliyuncs.com/id/synthetic-tenant/mcp`
    const metadata = { issuer, authorization_endpoint: `${signin}/authorize`, token_endpoint: `${oauth}/token` }
    configureNetworkPolicy(issuer)
    expect(configuredIssuer()).toBe(issuer)
    expect(() => assertAuthorizationMetadata(metadata)).not.toThrow()
    expect(() => assertAuthorizationMetadata({ ...metadata, issuer: issuer.replace('synthetic-tenant', 'other-tenant') })).toThrow(
      'built-in Alibaba Cloud OpenAPI MCP preset',
    )
    expect(() => assertAuthorizationMetadata({ ...metadata, token_endpoint: `${canary}/steal` })).toThrow('Untrusted')
    const otherOauth = region === 'cn-hangzhou' ? 'https://oauth.alibabacloud.com' : 'https://oauth.aliyun.com'
    expect(() => assertAllowedUrl(otherOauth)).toThrow('Untrusted')
    expect(canaryHits).toBe(0)
    const presetHash = getServerUrlHash(issuer)
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', issuer)
    expect(getServerUrlHash(issuer)).toBe(presetHash)
  })

  it.each([
    'https://openapi-mcp.cn-hangzhou.aliyuncs.com.attacker.test/id/tenant/mcp',
    'https://openapi-mcp.cn-hangzhou.aliyuncs.com:8443/id/tenant/mcp',
    'http://openapi-mcp.cn-hangzhou.aliyuncs.com/id/tenant/mcp',
    'https://openapi-mcp.cn-unknown.aliyuncs.com/id/tenant/mcp',
    'https://unrelated.aliyuncs.com/id/tenant/mcp',
    'https://openapi-mcp.cn-hangzhou.aliyuncs.com/other/tenant/mcp',
    'https://openapi-mcp.cn-hangzhou.aliyuncs.com/id/tenant/mcp/extra',
    'https://openapi-mcp.cn-hangzhou.aliyuncs.com/id/tenant%2Fother/mcp',
    'https://openapi-mcp.cn-hangzhou.aliyuncs.com/id/tenant/mcp?issuer=foreign',
    'https://user@openapi-mcp.cn-hangzhou.aliyuncs.com/id/tenant/mcp',
  ])('does not grant preset OAuth authority to %s', (server) => {
    delete process.env.MCP_REMOTE_TRUSTED_ORIGINS
    expect(() => {
      configureNetworkPolicy(server)
      assertAllowedUrl('https://oauth.aliyun.com/token')
    }).toThrow(/Untrusted|unsafe/)
  })

  it('lets explicit settings override the OpenAPI MCP preset without adding preset origins', () => {
    const server = 'https://openapi-mcp.cn-hangzhou.aliyuncs.com/id/tenant/mcp'
    delete process.env.MCP_REMOTE_TRUSTED_ORIGINS
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com/tenant')
    configureNetworkPolicy(server)
    expect(configuredIssuer()).toBe('https://auth.example.com/tenant')
    expect(() => assertAllowedUrl('https://oauth.aliyun.com/token')).toThrow('Untrusted')
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', '')
    configureNetworkPolicy(server, 'https://machine.example.com/token')
    expect(configuredIssuer()).toBe('https://machine.example.com')
    expect(() => assertAllowedUrl('https://oauth.aliyun.com/token')).toThrow('Untrusted')
    vi.stubEnv('MCP_REMOTE_TRUSTED_ORIGINS', '')
    configureNetworkPolicy(server)
    expect(configuredIssuer()).toBe(server)
    expect(() => assertAllowedUrl('https://oauth.aliyun.com/token')).toThrow('Untrusted')
  })

  it('explains the default origin mismatch without exposing tenant identifiers', () => {
    const server = 'https://mcp.example.com/id/private-tenant/mcp'
    configureNetworkPolicy(server)
    let message = ''
    try {
      assertAuthorizationMetadata({ issuer: server })
    } catch (error) {
      message = (error as Error).message
    }
    expect(message).toContain('refusing to release credentials')
    expect(message).toContain('MCP server origin (default); MCP_REMOTE_AUTH_ISSUER is not set')
    expect(message).toContain('including any path')
    expect(message).toContain('confirmed by the service operator')
    expect(message).not.toContain('private-tenant')
  })

  it('accepts the default root issuer for a path-bearing MCP resource', () => {
    configureNetworkPolicy('https://mcp.example.com/mcp')
    expect(() => assertAuthorizationMetadata({ issuer: 'https://mcp.example.com' })).not.toThrow()
  })

  it('distinguishes the token endpoint origin default from explicit issuer configuration', () => {
    configureNetworkPolicy('https://mcp.example.com/mcp', 'https://auth.example.com/token')
    expect(() => assertExpectedIssuer('https://auth.example.com/tenant')).toThrow(
      '--token-endpoint origin (default); MCP_REMOTE_AUTH_ISSUER is not set',
    )
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com/tenant')
    configureNetworkPolicy('https://mcp.example.com/mcp', 'https://auth.example.com/token')
    expect(() => assertExpectedIssuer('https://auth.example.com/other-tenant')).toThrow('MCP_REMOTE_AUTH_ISSUER (explicit configuration)')
    expect(() => assertExpectedIssuer('https://auth.example.com/tenant')).not.toThrow()
  })

  it('requires explicit trust for OAuth hosts even with a configured tenant issuer', () => {
    const issuer = 'https://mcp.example.com/id/synthetic-tenant/mcp'
    const metadata = {
      issuer,
      authorization_endpoint: 'https://signin.example.com/authorize',
      token_endpoint: 'https://oauth.example.com/token',
      registration_endpoint: 'https://mcp.example.com/register/id/synthetic-tenant',
    }
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', issuer)
    configureNetworkPolicy(issuer)
    expect(() => assertAuthorizationMetadata(metadata)).toThrow('Untrusted')
    vi.stubEnv('MCP_REMOTE_TRUSTED_ORIGINS', 'https://signin.example.com,https://oauth.example.com')
    configureNetworkPolicy(issuer)
    expect(() => assertAuthorizationMetadata(metadata)).not.toThrow()
    expect(() => assertAuthorizationMetadata({ ...metadata, issuer: 'https://mcp.example.com/id/other-tenant/mcp' })).toThrow(
      'issuer differs',
    )
    expect(() => assertAuthorizationMetadata({ ...metadata, token_endpoint: `${canary}/steal` })).toThrow('Untrusted')
    expect(canaryHits).toBe(0)
  })

  it('CVE-2026-51994: does not fetch a server-selected resource_metadata origin', async () => {
    expect(await discoverProtectedResourceMetadata(`${origin}/mcp`, `Bearer resource_metadata="${canary}/metadata"`)).toBeUndefined()
    expect(canaryHits).toBe(0)
  })

  it('CVE-2026-51995: does not probe a server-selected authorization server', async () => {
    mode = 'metadata'
    const metadata = await discoverProtectedResourceMetadata(`${origin}/mcp`)
    expect(metadata?.authorization_servers).toEqual([canary])
    expect(await fetchAuthorizationServerMetadata(metadata!.authorization_servers![0])).toBeUndefined()
    expect(canaryHits).toBe(0)
  })

  it('does not follow a metadata redirect to a canary', async () => {
    mode = 'redirect'
    expect(await discoverProtectedResourceMetadata(`${origin}/mcp`)).toBeUndefined()
    expect(await fetchAuthorizationServerMetadata(origin)).toBeUndefined()
    expect(canaryHits).toBe(0)
  })

  it('does not replay a POST body or Authorization header through a 307 redirect', async () => {
    mode = 'redirect'
    const response = await guardedFetch(`${origin}/token`, {
      method: 'POST',
      headers: { Authorization: 'Basic synthetic-secret' },
      body: 'refresh_token=synthetic-refresh-token',
      redirect: 'follow',
    })
    expect(response.status).toBe(307)
    expect(canaryHits).toBe(0)
  })

  it('also constrains the undici fetch handed to SDK transports', async () => {
    mode = 'redirect'
    expect((await fetchWithMcpHeaders(`${origin}/mcp`, { redirect: 'follow' })).status).toBe(307)
    await expect(fetchWithMcpHeaders(`${canary}/mcp`)).rejects.toThrow('Untrusted')
    expect(canaryHits).toBe(0)
  })

  it.each([
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1/',
    'http://2130706433/',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'https://mcp.example.com.attacker.test/',
  ])('blocks an unconfigured destination: %s', (url) => {
    expect(() => assertAllowedUrl(url)).toThrow('Untrusted')
  })

  it.each(['file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@example.com/', 'https://example.com/#secret'])(
    'rejects unsafe URL syntax: %s',
    (url) => expect(() => assertAllowedUrl(url)).toThrow('unsafe'),
  )

  it('permits only operator-configured cross-origin metadata and issuer destinations', () => {
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com/tenant')
    vi.stubEnv('MCP_REMOTE_TRUSTED_ORIGINS', 'https://metadata.example.com')
    configureNetworkPolicy('https://mcp.example.com/mcp')
    expect(() => assertAllowedUrl('https://metadata.example.com/prm')).not.toThrow()
    expect(() => assertExpectedIssuer('https://auth.example.com/tenant')).not.toThrow()
    expect(() => assertExpectedIssuer('https://auth.example.com/other-tenant')).toThrow('issuer differs')
    expect(() => assertAllowedUrl('https://auth.example.com:8443/token')).toThrow('Untrusted')
    expect(() => assertAllowedUrl('http://auth.example.com/token')).toThrow('Untrusted')
  })

  it('rejects wildcard and path-bearing trust configuration', () => {
    vi.stubEnv('MCP_REMOTE_TRUSTED_ORIGINS', 'https://auth.example.com/hidden/path')
    expect(() => configureNetworkPolicy(origin)).toThrow('exact origins')
  })

  it('does not accept an OAuth endpoint on the MCP origin when another issuer owns the credentials', () => {
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com')
    configureNetworkPolicy(origin)
    expect(() => assertAuthorizationMetadata({ issuer: 'https://auth.example.com', token_endpoint: `${origin}/steal` })).toThrow(
      'outside the configured authorization',
    )
  })

  it('refuses a server-selected secret recipient on the custom client_credentials path', async () => {
    await expect(
      authorizeWithClientCredentials({
        metadata: { issuer: origin, token_endpoint: `${canary}/token` },
        clientInformation: { client_id: 'synthetic-client', client_secret: 'synthetic-secret' },
      }),
    ).rejects.toThrow('Untrusted')
    expect(canaryHits).toBe(0)
  })

  it('CVE-2026-104850: refuses to stamp static credentials with an attacker-selected issuer', async () => {
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com')
    configureNetworkPolicy(origin)
    const provider = new NodeOAuthClientProvider({
      serverUrl: origin,
      callbackPort: 3333,
      host: '127.0.0.1',
      serverUrlHash: 'synthetic-client',
      staticOAuthClientInfo: { client_id: 'synthetic-client', client_secret: 'synthetic-secret', redirect_uris: [] },
    })
    await expect(provider.clientInformation({ issuer: origin })).rejects.toThrow('issuer differs')
  })

  it('CVE-2026-51997: blocks an untrusted browser destination before invoking any opener', async () => {
    await expect(openBrowser(`${canary}/authorize`)).rejects.toThrow('Untrusted')
    await expect(openBrowser('file:///tmp/payload')).rejects.toThrow('unsafe')
    expect(open).not.toHaveBeenCalled()
  })

  it('CVE-2026-52001: compares exact origins before allowing SSE credentials', () => {
    expect(() => assertResourceOrigin(`${canary}/events`, origin)).toThrow('across origins')
    expect(() => assertResourceOrigin(`${origin}/events`, origin)).not.toThrow()
    expect(() => assertResourceOrigin('https://example.com:8443/events', 'https://example.com/mcp')).toThrow('across origins')
  })

  it('strips MCP headers from OAuth requests while preserving generated client authentication', async () => {
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com')
    configureNetworkPolicy('https://mcp.example.com/mcp')
    const previous = getGlobalDispatcher()
    const mock = new MockAgent()
    mock.disableNetConnect()
    setGlobalDispatcher(mock)
    let sentHeaders: unknown
    mock
      .get('https://auth.example.com')
      .intercept({ path: '/token', method: 'POST' })
      .reply(200, (request) => {
        sentHeaders = request.headers
        return '{}'
      })
    try {
      const request = createResourceFetch('https://mcp.example.com/mcp', {
        Authorization: 'Bearer resource-secret',
        'X-Api-Key': 'resource-api-key',
      })
      await request('https://auth.example.com/token', {
        method: 'POST',
        headers: { Authorization: 'Basic oauth-client-secret', 'X-Api-Key': 'resource-api-key' },
      })
      expect(JSON.stringify(sentHeaders)).toContain('Basic oauth-client-secret')
      expect(JSON.stringify(sentHeaders)).not.toContain('resource-api-key')
      expect(JSON.stringify(sentHeaders)).not.toContain('Bearer resource-secret')
      mock.assertNoPendingInterceptors()
    } finally {
      setGlobalDispatcher(previous)
      await mock.close()
    }
  })

  it('does not refresh a foreign or unstamped cached token before checking its issuer', async () => {
    const configDir = await mkdtemp(path.join(tmpdir(), 'mcp-issuer-test-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    const provider = new NodeOAuthClientProvider({
      serverUrl: origin,
      callbackPort: 3333,
      host: '127.0.0.1',
      serverUrlHash: 'synthetic-token',
      authorizationServerMetadata: { issuer: origin, token_endpoint: `${canary}/steal` },
    })
    try {
      for (const issuer of [undefined, 'https://foreign.example.com']) {
        await writeJsonFile('synthetic-token', 'tokens.json', {
          access_token: 'synthetic-access',
          refresh_token: 'synthetic-refresh',
          token_type: 'Bearer',
          expires_at: Date.now() - 60_000,
          issuer,
        })
        expect(await provider.tokens()).toBeUndefined()
      }
      expect(canaryHits).toBe(0)
    } finally {
      await rm(configDir, { recursive: true, force: true })
    }
  })

  it('CVE-2026-51996: uses SHA-256 and separates fields without delimiter aliasing', () => {
    expect(getServerUrlHash(origin)).toMatch(/^[a-f0-9]{64}$/)
    expect(getServerUrlHash(`${origin}/a|b`)).not.toBe(getServerUrlHash(`${origin}/a`, 'b'))
    const oldIssuerHash = getServerUrlHash(origin)
    vi.stubEnv('MCP_REMOTE_AUTH_ISSUER', 'https://auth.example.com')
    expect(getServerUrlHash(origin)).not.toBe(oldIssuerHash)
  })
})
