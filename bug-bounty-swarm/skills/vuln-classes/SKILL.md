# Vulnerability Classes Skillbook

## 1) IDOR
- Signals: object ID in path/query/body, authorization gaps
- Bypasses: numeric increment/decrement, UUID mutation, parameter pollution

## 2) SSRF
- Signals: URL fetchers, webhook endpoints, proxy features
- Bypasses: decimal/octal/IPv6/embedded-auth metadata host representations

## 3) XSS
- Signals: unescaped reflection, DOM sinks (`innerHTML`, `document.write`)
- Bypasses: polyglots, quote-break payloads, context-specific payloads

## 4) OAuth
- Signals: missing `state`, weak `redirect_uri` validation, PKCE flaws
- Bypasses: nested redirect domains, PKCE verifier omissions

## 5) Race Conditions
- Signals: state-changing endpoints with non-idempotent behavior
- Bypasses: concurrent request bursts, mixed token replay

## 6) SQLi
- Signals: SQL error messages, timing deltas, boolean differences
- Bypasses: case toggling, inline comments, encoded payloads

## 7) SSTI
- Signals: template evaluation artifacts (`{{7*7}} => 49`)
- Bypasses: filter evasion and alternate syntax per template engine

## 8) Open Redirect
- Signals: user-controlled redirect parameters
- Bypasses: protocol-relative URLs, mixed encoding, nested redirects

## 9) XXE
- Signals: XML upload/parse endpoints
- Bypasses: external entities with local/remote references

## 10) CSRF
- Signals: state changes without anti-CSRF tokens
- Bypasses: token reuse, same-site misconfiguration

## 11) Insecure Deserialization
- Signals: serialized blobs in cookies/body
- Bypasses: gadget chains and signed-token confusion

## 12) Business Logic
- Signals: price tampering, workflow skips, role manipulation
- Bypasses: negative values, order of operations abuse, privilege parameter injection
