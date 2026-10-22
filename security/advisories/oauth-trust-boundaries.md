# OAuth trust boundaries in mcp-remote-alibaba-cloud

Assessment date: 2026-10-22. Package: npm `mcp-remote-alibaba-cloud`.
Confirmed affected artifact: **0.1.38**, npm gitHead
`2a5fa21354aa61a53c37df2940a8b38b5ecd1f01`.
Prepared remediation version: **0.1.39 (unpublished)**.
This document is a repository advisory draft for publication under the fork's own package name.
It does not create a GHSA/OSV package mapping or update vulnerability databases.

## Provenance and upstream merge

The 0.1.38 fork differs from upstream commit
`02619aff36e79803d7c894e8c8ae7b34b2d11f8c` only in `package.json`.
The remediation merges upstream main
`373f7320f6afd1fdb00e0168826a3cea99102241` (after upstream v0.15.2), preserving
the fork's npm name, repository, and binary names. It bundles MCP client/core/server 2.3.1;
the minimum permitted version is 2.3.0. An upstream merge alone is not treated as remediation.

## Assessment of the reported records

Scores below are CISA-ADP CVSS 3.1 as published in the CVE records, not independently assigned scores.
Official descriptions and researcher evidence have different strength; no arbitrary-code execution
or access to real secrets was demonstrated in this assessment.

| Record                                                            | Published upstream range | CISA score   | Evidence and change in this fork                                                                                                                                                                                                                               |
| ----------------------------------------------------------------- | ------------------------ | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CVE-2026-51994](https://www.cve.org/CVERecord?id=CVE-2026-51994) | 0.1.32–0.1.38            | 9.1 Critical | `resource_metadata` was fetched without a destination restriction. Added operator-controlled exact-origin policy before fetching.                                                                                                                              |
| [CVE-2026-51995](https://www.cve.org/CVERecord?id=CVE-2026-51995) | 0.1.32–0.1.38            | 7.5 High     | `authorization_servers[]` could select the next metadata destination. The same policy now constrains this request and OAuth endpoints.                                                                                                                         |
| [CVE-2026-51996](https://www.cve.org/CVERecord?id=CVE-2026-51996) | 0.1.16–0.1.38            | 9.8 Critical | MD5 storage namespaces confirmed in source. Research classifies this as defense in depth, not a demonstrated chosen-URL collision or RCE. Replaced MD5 with SHA-256 over named, serialized fields, including configured issuer; no legacy cache migration.     |
| [CVE-2026-51997](https://www.cve.org/CVERecord?id=CVE-2026-51997) | 0.1.16–0.1.38            | 8.8 High     | Browser destination lacked an origin policy. Validate scheme, userinfo, fragments and trusted origin before calling any opener. No browser/OS code-execution exploit was run.                                                                                  |
| [CVE-2026-52001](https://www.cve.org/CVERecord?id=CVE-2026-52001) | 0.1.18–0.1.38            | 7.5 High     | SSE wrapper attached bearer credentials without its own origin check. Added an exact resource-origin check before reading tokens and disabled automatic redirects. Research describes this as transport hardening, not a demonstrated cross-origin SSE bypass. |

The SDK's additional [CVE-2026-104850](https://www.cve.org/CVERecord?id=CVE-2026-104850)
affects SDK 1.x before 1.31.0 and client 2.x before 2.2.0. The original fork bundles SDK 1.25.3.
The updated dependency floor exceeds the patched 2.2.0 release and also includes 2.3.0's redirect
policy. The fork additionally checks the operator-selected issuer before returning static client
credentials, checks cached token issuer before proactive refresh, validates credential endpoint
origins, and preserves issuer stamps when storing tokens. It no longer stamps static credentials
with an arbitrary issuer selected by the remote MCP server.

## Additional restrictions and compatibility

Both CLI entry points initialize the policy before discovery or transport I/O. Only configuration
can expand it: the MCP URL, `MCP_REMOTE_AUTH_ISSUER`, `MCP_REMOTE_TRUSTED_ORIGINS`, and the explicit
`--token-endpoint`. New metadata never expands the policy. HTTP cross-origin discovery is rejected.
A configured separate issuer does not implicitly authorize credential delivery to the MCP origin.

Direct discovery and grant requests use manual redirects; the SDK handles its permitted
same-origin transport redirects through the guarded fetch function. The SSE wrapper additionally
refuses any stream destination outside the resource origin. Operator-supplied MCP headers are
scoped to the resource origin rather than forwarded into a separate OAuth service.

This is intentionally stricter than automatic arbitrary cross-origin discovery. Operators must
configure their trusted issuer and any additional service origins, and may need to replace a
redirecting discovery URL with its final URL. The new cache namespace requires a fresh sign-in;
static registrations should explicitly select their registered callback port.

Origin trust is not an IP/DNS sandbox: explicitly configured private services, DNS, TLS, proxies,
and navigation after handing an approved URL to a browser remain trusted. Filesystem permissions
protect the plaintext credential store; this patch does not add keychain encryption.

## Validation and publication

Local regression tests use loopback canaries and synthetic credentials only. They cover malicious
resource metadata and authorization-server URLs, metadata and token POST redirects, the SDK fetch
wrapper, issuer mismatch for static credentials, credential endpoint origin checks, browser launch
rejection, SSE origin comparison, and storage namespace separation. No Alibaba Cloud system is probed.
The original protected-resource and authorization-server discovery helpers from the published
0.1.38 gitHead were also executed against two local listeners (only their debug logger import
was stubbed): the original helpers made two canary requests; the patched helpers made zero.

Validation completed: formatting, lint/type checks, unused-code checks, production build,
25 security regressions, and 13 local OAuth/concurrency/protocol integration scenarios.
The public package was packed locally and both CLI binaries returned version 0.1.39.
The dependency audit could not complete: the configured registry has no audit endpoint and
the public registry request timed out. These checks are not a claim that every dependency is
free of other vulnerabilities.

Before announcing a released fix, publish the tested npm artifact and a GitHub Security Advisory
that explicitly maps the affected fork package name and version 0.1.38 to the released fixed version.
Reference all five upstream records in that advisory; this repository document alone does not make
scanners match the fork. Do not infer affected ranges for other fork versions from upstream numbering.

Sources: [research advisories and corrections](https://github.com/playb0t/mcp-remote-oauth-security),
[SDK advisory](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-6qxp-vccf-f47h),
[upstream source](https://github.com/punkpeye/mcp-remote/tree/373f7320f6afd1fdb00e0168826a3cea99102241).
