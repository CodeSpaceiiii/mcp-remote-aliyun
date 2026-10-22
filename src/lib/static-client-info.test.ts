import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { auth } from '@modelcontextprotocol/client'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import { getConfigFilePath, writeJsonFile } from './mcp-auth-config'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: 'test',
  buildRedirectUrl: (host: string, port: number, path: string) => `http://${host}:${port}${path}`,
}))
// A sign-in must never reach for a real browser (or its platform fallbacks) under test.
vi.mock('./open-browser', () => ({ openBrowser: vi.fn().mockResolvedValue(false) }))
vi.mock('./authorization-server-metadata', () => ({ fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined) }))

const serverUrl = 'https://mcp.example.test/mcp'
const authorizationServerUrl = 'https://as.example.test'
const serverUrlHash = 'static-client-info-test'
// The shape the README documents. The flag passes it through as parsed, without redirect_uris.
const pinnedClient = { client_id: 'pinned-client', client_secret: 'pinned-secret' }

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/** Answers discovery, registration and token requests like a real OAuth deployment would. */
class TestNetwork {
  registrationRequests: string[] = []
  tokenRequests: URLSearchParams[] = []

  fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init)

    switch (request.url) {
      case 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp':
        return json(200, { resource: serverUrl, authorization_servers: [authorizationServerUrl] })
      case `${authorizationServerUrl}/.well-known/oauth-authorization-server`:
        return json(200, {
          issuer: authorizationServerUrl,
          authorization_endpoint: `${authorizationServerUrl}/authorize`,
          token_endpoint: `${authorizationServerUrl}/token`,
          registration_endpoint: `${authorizationServerUrl}/register`,
          response_types_supported: ['code'],
          token_endpoint_auth_methods_supported: ['client_secret_post'],
        })
      case `${authorizationServerUrl}/register`:
        this.registrationRequests.push(request.url)
        return json(200, { client_id: 'registered-client', ...(await request.json()) })
      case `${authorizationServerUrl}/token`:
        this.tokenRequests.push(new URLSearchParams(await request.text()))
        return json(200, { access_token: 'issued-1', token_type: 'Bearer', expires_in: 3600 })
      default:
        return new Response('not found', { status: 404 })
    }
  }
}

const clientInfoFile = () => readFile(getConfigFilePath(serverUrlHash, 'client_info.json'), 'utf8')

/**
 * A client pinned with --static-oauth-client-info comes from the command line on every run, often
 * with its secret expanded from an environment variable so it never sits anywhere readable. The
 * credential store is no place for it: it would only be a copy of that secret, and one a later run
 * without the flag would mistake for a registration of its own.
 */
describe('NodeOAuthClientProvider - a client pinned with --static-oauth-client-info', () => {
  let configDir: string
  let network: TestNetwork

  beforeEach(async () => {
    configDir = await mkdtemp(join(tmpdir(), 'mcp-remote-static-client-'))
    vi.stubEnv('MCP_REMOTE_CONFIG_DIR', configDir)
    network = new TestNetwork()
    vi.stubGlobal('fetch', network.fetch)
  })

  afterEach(async () => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    await rm(configDir, { recursive: true, force: true })
  })

  const provider = () =>
    new NodeOAuthClientProvider({
      serverUrl,
      serverUrlHash,
      host: 'localhost',
      callbackPort: 0,
      staticOAuthClientInfo: pinnedClient as any,
    })

  it('signs in with the pinned client without saving it or warning that it carries no issuer stamp', async () => {
    const warn = vi.spyOn(console, 'warn')
    const signingIn = provider()

    await expect(auth(signingIn, { serverUrl, fetchFn: network.fetch })).resolves.toBe('REDIRECT')
    await expect(auth(signingIn, { serverUrl, authorizationCode: 'code-1', fetchFn: network.fetch })).resolves.toBe('AUTHORIZED')

    expect(network.registrationRequests).toEqual([])
    expect(network.tokenRequests.map((params) => params.get('client_id'))).toEqual(['pinned-client'])
    await expect(clientInfoFile()).rejects.toMatchObject({ code: 'ENOENT' })
    expect(warn).not.toHaveBeenCalledWith(expect.stringContaining("no 'issuer' stamp"))
  })

  it('does not cache the pinned client when the SDK offers it back to save', async () => {
    await provider().saveClientInformation({ ...pinnedClient, issuer: authorizationServerUrl } as any)

    await expect(clientInfoFile()).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('removes the copy of the pinned client that earlier versions saved', async () => {
    await writeJsonFile(serverUrlHash, 'client_info.json', { ...pinnedClient, issuer: authorizationServerUrl })

    await provider().clientInformation()

    await expect(clientInfoFile()).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('leaves a registration of another client where it is', async () => {
    // Registered before the flag was passed, and in use again once it is dropped
    const registration = {
      client_id: 'registered-client',
      redirect_uris: ['http://localhost:0/oauth/callback'],
      issuer: authorizationServerUrl,
    }
    await writeJsonFile(serverUrlHash, 'client_info.json', registration)

    await provider().clientInformation()

    expect(JSON.parse(await clientInfoFile())).toEqual(registration)
  })
})
