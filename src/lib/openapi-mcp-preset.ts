/**
 * Fixed service presets, selected only from the operator's MCP URL, never discovery.
 * Official CN/INTL entry points:
 * https://help.aliyun.com/zh/openapi/use-aliyun-mcp-proxy-agent-openapi-mcp-server
 */
const services = new Map([
  ['https://openapi-mcp.cn-hangzhou.aliyuncs.com', ['https://signin.aliyun.com', 'https://oauth.aliyun.com']],
  ['https://openapi-mcp.ap-southeast-1.aliyuncs.com', ['https://signin.alibabacloud.com', 'https://oauth.alibabacloud.com']],
])

export function getOpenApiMcpPreset(serverUrl: string, tokenEndpoint?: string): { issuer: string; trustedOrigins: string[] } | undefined {
  // Explicit issuer/token service configuration retains its existing meaning.
  if (process.env.MCP_REMOTE_AUTH_ISSUER || tokenEndpoint) return undefined
  let server: URL
  try {
    server = new URL(serverUrl)
  } catch {
    return undefined
  }
  const trustedOrigins = services.get(server.origin)
  if (
    !trustedOrigins ||
    server.username ||
    server.password ||
    server.search ||
    server.hash ||
    !/^\/id\/[A-Za-z0-9_-]+\/mcp$/.test(server.pathname)
  ) {
    return undefined
  }
  return { issuer: server.href, trustedOrigins }
}
