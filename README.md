# SquidSec AI Bridge

Burp Suite extension that exposes a **loopback MCP and JSON HTTP API** so an LLM agent can use the live Burp project.

Default bind: `http://127.0.0.1:9877`  
Auth: bearer token generated on first load. Copy it from the **AI Bridge** suite tab.

Scanner and Collaborator features need Burp Suite Professional. They fail cleanly on Community Edition.

## What it does

- MCP tool discovery: `GET /mcp/tools` and JSON-RPC `POST /mcp`
- Scope check / include / exclude
- Proxy history, intercept, WebSocket history
- Match/replace rewrite rules
- Send to Repeater, Intruder, Organizer, Comparer, Decoder
- HTTP send through Burp (optional via proxy so it lands in Proxy History)
- Sitemap, cookies, annotations, search
- Scanner crawl / audit / issues / report (Pro)
- Collaborator payload + poll (Pro)
- Engagement helpers: curl, finding draft, endpoint map, CSRF PoC, decode, program-JSON scope, evidence pack

## Build

Requires JDK 17+.

```bash
./gradlew test jar
```

Output: `build/libs/burp-ai-bridge-2.0.0.jar`

## Install in Burp

1. Extensions → Installed → Add
2. Type: Java
3. Select the JAR
4. Open the **AI Bridge** tab and copy the token / LLM connection info
5. Health check (no auth): `GET http://127.0.0.1:9877/health`

Keep listen host on `127.0.0.1` unless you need WSL. Do not expose the listener to untrusted networks.

## MCP

```bash
curl -sS http://127.0.0.1:9877/mcp/tools
curl -sS -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  http://127.0.0.1:9877/mcp
curl -sS -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"burp_bridge_health","arguments":{}}' \
  http://127.0.0.1:9877/mcp/call
```

Turn Proxy intercept **off** before automated `/http/send` or the call will hang.

## Security

- Loopback only by default
- Token required for mutating and reading project data
- Treat HTTP message bodies as untrusted
- Finding helpers redact common secret headers
- Use only against systems you are authorized to test

## BApp Store

See `BappManifest.bmf`, `BappDescription.html`, and `SUBMISSION.md`.

## License

Apache License 2.0. SquidSec — U.S. Veteran-Owned. https://www.SquidOffense.com
