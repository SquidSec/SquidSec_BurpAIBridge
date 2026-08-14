package com.squidsec.burp.bridge;

/** Plain-text block an operator can paste into an LLM harness. */
public final class LlmConnectionText {

    private LlmConnectionText() {}

    public static String build(BridgeConfig config, int boundPort) {
        String token = config == null ? "" : config.token();
        int port = boundPort > 0 ? boundPort : (config == null ? BridgeConfig.DEFAULT_PORT : config.port());
        String loopback = "http://127.0.0.1:" + port;
        boolean wslBind = config != null && config.listensForWsl();

        StringBuilder sb = new StringBuilder();
        sb.append("SquidSec Burp AI Bridge connection\n");
        sb.append("Version: ").append(BridgeVersion.VERSION).append('\n');
        sb.append('\n');
        sb.append("Base URL (Windows / localhost): ").append(loopback).append('\n');
        if (wslBind) {
            sb.append("Listening on 0.0.0.0:").append(port);
            sb.append(" so WSL and other hosts can connect.\n");
        } else {
            sb.append("Listening on 127.0.0.1 only. Enable \"Listen on all interfaces (WSL)\" in the AI Bridge tab if WSL cannot reach this.\n");
        }
        sb.append("Auth token: ").append(token).append('\n');
        sb.append('\n');
        sb.append("Every request:\n");
        sb.append("  Authorization: Bearer ").append(token).append('\n');
        sb.append("  or X-API-Key: ").append(token).append('\n');
        sb.append("Health (no auth): GET ").append(loopback).append("/health\n");
        sb.append("MCP tools (no auth): GET ").append(loopback).append("/mcp/tools\n");
        sb.append("MCP JSON-RPC: POST ").append(loopback).append("/mcp\n");
        sb.append("MCP call: POST ").append(loopback).append("/mcp/call  {\"name\":\"...\",\"arguments\":{}}\n");
        sb.append('\n');
        sb.append("WSL (Burp is on Windows):\n");
        sb.append("  Try localhost first (Windows localhost forwarding):\n");
        sb.append("    export BURP_BRIDGE_BASE=").append(loopback).append('\n');
        sb.append("    export BURP_BRIDGE_TOKEN=").append(token).append('\n');
        sb.append("  If that fails, use the Windows host IP and listen on 0.0.0.0:\n");
        sb.append("    WINIP=$(grep nameserver /etc/resolv.conf | awk '{print $2}')\n");
        sb.append("    export BURP_BRIDGE_BASE=http://$WINIP:").append(port).append('\n');
        sb.append("    export BURP_BRIDGE_TOKEN=").append(token).append('\n');
        sb.append("  Endpoint file (if present): ~/.squidsec/burp-ai-bridge.json\n");
        sb.append("  or /mnt/c/Users/<you>/.squidsec/burp-ai-bridge.json\n");
        sb.append('\n');
        sb.append("curl examples:\n");
        sb.append("  curl -sS ").append(loopback).append("/health\n");
        sb.append("  curl -sS -H \"Authorization: Bearer ").append(token).append("\" ");
        sb.append(loopback).append("/proxy/history\n");
        sb.append("  curl -sS -H \"Authorization: Bearer ").append(token).append("\" ");
        sb.append("-H \"Content-Type: application/json\" ");
        sb.append("-d '{\"url\":\"https://example.com/\"}' ");
        sb.append(loopback).append("/http/send\n");
        sb.append('\n');
        sb.append("API (auth required except /health and /):\n");
        sb.append("  GET  /health\n");
        sb.append("  GET  /scope/check?url=\n");
        sb.append("  POST /scope/include   {\"url\":\"...\"}\n");
        sb.append("  POST /scope/exclude   {\"url\":\"...\"}\n");
        sb.append("  GET/POST /proxy/intercept\n");
        sb.append("  GET  /proxy/history   (offset,limit,host,method,status,contains,inScope,format=http|json)\n");
        sb.append("  GET  /proxy/history/item?index=\n");
        sb.append("  GET/POST /rewrite/rules\n");
        sb.append("  POST /repeater        {raw|request, host, port, https, tabName}\n");
        sb.append("  POST /intruder        {raw|request, host, port, https, tabName}\n");
        sb.append("  POST /http/send       send via Burp; also lands in Proxy History when send-via-proxy is on\n");
        sb.append("  GET  /sitemap\n");
        sb.append("  GET  /mcp/tools      discover tools (name, description, inputSchema)\n");
        sb.append("  POST /mcp            JSON-RPC initialize / tools/list / tools/call / ping\n");
        sb.append("  POST /mcp/call       {\"name\":\"burp_http_send\",\"arguments\":{...}}\n");
        sb.append('\n');
        sb.append("Rules for the LLM:\n");
        sb.append("- On connect, GET /mcp/tools or POST /mcp {\"method\":\"tools/list\"} and use only those tools.\n");
        sb.append("- Use this bridge for live Burp traffic. Do not invent requests you did not send.\n");
        sb.append("- Prefer /http/send so the exchange is in Burp Proxy History and the project file.\n");
        sb.append("- Turn Proxy intercept OFF before automated /http/send or the call will hang.\n");
        sb.append("- Redact cookies, tokens, and secrets in anything you write back to the operator.\n");
        return sb.toString();
    }
}
