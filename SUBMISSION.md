# BApp Store submission

PortSwigger review is a GitHub issue, not a JAR upload.

1. This repo is the source: https://github.com/SquidSec/SquidSec_BurpAIBridge
2. Open a **New extension submission** issue: https://github.com/PortSwigger/extension-portal/issues/new/choose
3. Fill the form with the answers below.
4. Track: https://github.com/orgs/PortSwigger/projects/1/views/1

## Form answers

**Extension URL:** https://github.com/SquidSec/SquidSec_BurpAIBridge

**Version number:** 2.0.0

**Compatible products:** Community (yes). DAST (no). Burp AI (no).

**Author display name:** SquidSec

**Contact (optional, public):** leave blank, or use a public address you are willing to publish.

**Confirm:** you have permission to publish under the PortSwigger EULA, and you have read the acceptance criteria.

**Extension overview:**

SquidSec AI Bridge is a local MCP and JSON HTTP API for Burp Suite. An LLM agent can discover tools (`GET /mcp/tools`) and drive the live project: scope, proxy history, send, Repeater, Intruder, sitemap, Organizer, WebSockets, cookies, Scanner (Pro), and Collaborator (Pro). It binds to 127.0.0.1 by default and requires a bearer token for mutating calls.

**Key features:**

- MCP discovery and JSON-RPC (`/mcp`, `/mcp/tools`, `/mcp/call`)
- Scope, proxy history, intercept, rewrite rules
- HTTP send through Burp, optional via the proxy listener
- Repeater / Intruder / Organizer / Comparer / Decoder
- Scanner crawl, audit, issues, report (Pro)
- Collaborator payload and poll (Pro)
- Curl, finding draft, CSRF PoC, endpoint map, search
- Suite tab with settings, history, copy-for-LLM
- Unloads cleanly. Community-safe (Pro APIs fail soft).

**Usage instructions:**

1. Build with JDK 17: `./gradlew jar`
2. Burp → Extensions → Add → Java → `build/libs/burp-ai-bridge-2.0.0.jar`
3. Open the AI Bridge tab. Copy the token.
4. Confirm `GET http://127.0.0.1:9877/health`
5. Agent: `GET /mcp/tools` then authenticated `POST /mcp/call`
6. Leave listen host on 127.0.0.1. Turn intercept off before automated send.
