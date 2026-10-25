# Security policy

`mcp-remote-alibaba-cloud` is a fork that bundles upstream MCP client code. Vulnerabilities
reported under `mcp-remote` and the bundled MCP SDK can also affect this package; a scanner
that only checks the fork's npm name may miss them.

See [OAuth trust-boundary advisory](security/advisories/oauth-trust-boundaries.md) for the
assessment of npm 0.1.38 and the changes prepared for 0.1.39. A source commit is not an npm
release or a published GitHub Security Advisory.

Prefer native remote MCP support. Otherwise connect only to trusted MCP servers, explicitly
configure the expected authorization issuer, and keep additional trusted origins minimal.
The operator-configured destinations, their DNS and TLS, the operating system browser opener,
and any configured network proxy remain trusted. Fixed presets for the exact official Hangzhou
and Singapore OpenAPI MCP tenant URLs add their known OAuth origins when no explicit issuer or
token endpoint is configured; see the README for
the matching rules and overrides. The origin policy prevents discovery from
adding new destinations; it is not a DNS/IP sandbox for explicitly trusted domains.

OAuth cache files contain sensitive tokens in plaintext. The upstream owner-only permissions
remain in place. Do not share the cache or debug logs, and revoke credentials if compromise
is suspected. This release intentionally does not migrate legacy MD5 credential namespaces.

For a new issue, use the repository's private vulnerability reporting facility if enabled:
https://github.com/CodeSpaceiiii/mcp-remote-aliyun/security/advisories/new
Do not post live tokens, credentials, or private endpoint details in public issues.
