# BApp Store acceptance (PortSwigger)

Checked against https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria

| # | Criterion | How this extension meets it |
|---|-----------|------------------------------|
| 1 | Unique function | Local MCP + JSON API for live Burp. Not a scan check clone. Agents discover tools via `/mcp/tools`. |
| 2 | Clear name | **SquidSec AI Bridge**. Short: MCP/HTTP API so an agent can drive the live Burp project. |
| 3 | Operates securely | Default bind `127.0.0.1`. Bearer token for project data. No `Access-Control-Allow-Origin: *`. HTTP bodies treated as untrusted (redact helpers). Token is not printed to Extender output. |
| 4 | Includes dependencies | Fat-free JAR. Montoya API is `compileOnly` (provided by Burp). No extra runtime libs. |
| 5 | Threads | HTTP listener and tool calls run on daemon worker threads, not the Swing EDT. Context-menu Organizer send is a background thread. Worker exceptions are caught and written to the extension error stream. Rewrite handlers do string replace only. |
| 6 | Unloads cleanly | `registerUnloadingHandler` stops the `ServerSocket` and thread pools. |
| 7 | Burp networking | Target traffic uses `api.http().sendRequest()`. No `java.net.URL` to the target. |
| 8 | Offline | No online vuln-feed or license check. Works with no Internet. |
| 9 | Large projects | History/sitemap listing is capped. Sitemap uses `SiteMapFilter.prefixFilter` when a prefix is set. Results are not stored as long-lived references. |
| 10 | GUI parent | Dialogs use `SwingUtils.suiteFrame()` when available. |
| 11 | Montoya + Gradle | `net.portswigger.burp.extensions:montoya-api` via Gradle. |
| 12 | Burp AI default | **Not an AI-calling extension.** It does not prompt an LLM, Burp AI, or a third-party model. External agents talk to the local API. |

## Name vs existing BApps

This is an agent control plane for Burp (MCP). It is not Logger++, Autorize, or Turbo Intruder.
