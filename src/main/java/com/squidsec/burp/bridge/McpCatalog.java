package com.squidsec.burp.bridge;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** MCP tool list an agent can discover from the bridge. */
public final class McpCatalog {

    private McpCatalog() {}

    public static List<Map<String, Object>> tools() {
        List<Map<String, Object>> tools = new ArrayList<>();
        tools.add(tool("burp_bridge_health", "Check SquidSec Burp AI Bridge connectivity and intercept status.", obj(), List.of()));
        tools.add(tool("burp_scope_check", "Check whether a URL is in Burp suite-wide target scope (live).", props(p("url", "string", "Target URL")), List.of("url")));
        tools.add(tool("burp_scope_include", "Include a URL in Burp suite-wide target scope.", props(p("url", "string", "URL to include")), List.of("url")));
        tools.add(tool("burp_scope_exclude", "Exclude a URL from Burp suite-wide target scope.", props(p("url", "string", "URL to exclude")), List.of("url")));
        tools.add(tool("burp_proxy_intercept_get", "Get whether Burp Proxy master intercept is enabled.", obj(), List.of()));
        tools.add(tool(
                "burp_proxy_intercept_set",
                "Enable or disable Burp Proxy master intercept.",
                props(p("enabled", "boolean", "true to enable intercept")),
                List.of("enabled")));
        Map<String, Object> hist = obj();
        hist.putAll(props(
                p("offset", "integer", "Skip this many newest items"),
                p("limit", "integer", "Max items"),
                p("host", "string", "Host filter"),
                p("method", "string", "HTTP method"),
                p("status", "string", "Status code"),
                p("contains", "string", "Raw text filter"),
                p("urlContains", "string", "URL substring"),
                p("inScopeOnly", "boolean", "Only in-scope items"),
                p("inScope", "boolean", "Alias for inScopeOnly"),
                p("includeBody", "boolean", "Include bodies"),
                p("bodyLimit", "integer", "Max body bytes"),
                p("format", "string", "http (default) or json")));
        tools.add(tool(
                "burp_proxy_history",
                "Read and filter Burp Proxy HTTP history (newest first). format=http returns raw request/response.",
                hist,
                List.of()));
        tools.add(tool(
                "burp_proxy_history_item",
                "Get a single proxy history item by index.",
                props(
                        p("index", "integer", "History index"),
                        p("id", "integer", "Alias for index"),
                        p("includeBody", "boolean", null),
                        p("bodyLimit", "integer", null),
                        p("format", "string", "http or json")),
                List.of()));
        tools.add(tool("burp_rewrite_list", "List active proxy match/replace rewrite rules.", obj(), List.of()));
        tools.add(tool(
                "burp_rewrite_add",
                "Add a match/replace rewrite rule for proxied REQUEST/RESPONSE/BOTH traffic.",
                props(
                        p("match", "string", "Text or regex to match"),
                        p("replace", "string", "Replacement"),
                        p("phase", "string", "REQUEST, RESPONSE, or BOTH"),
                        p("regex", "boolean", null),
                        p("urlContains", "string", null),
                        p("name", "string", null),
                        p("enabled", "boolean", null),
                        p("id", "string", null)),
                List.of("match")));
        tools.add(tool("burp_rewrite_delete", "Delete a rewrite rule by id.", props(p("id", "string", "Rule id")), List.of("id")));
        tools.add(tool("burp_rewrite_clear", "Clear all rewrite rules.", obj(), List.of()));
        tools.add(tool(
                "burp_send_to_repeater",
                "Send a raw HTTP request to Burp Repeater.",
                props(
                        p("raw", "string", "Full raw HTTP request"),
                        p("host", "string", null),
                        p("port", "integer", null),
                        p("https", "boolean", null),
                        p("tabName", "string", null)),
                List.of("raw")));
        tools.add(tool(
                "burp_send_to_intruder",
                "Send a raw HTTP request to Burp Intruder.",
                props(
                        p("raw", "string", "Full raw HTTP request"),
                        p("host", "string", null),
                        p("port", "integer", null),
                        p("https", "boolean", null),
                        p("tabName", "string", null)),
                List.of("raw")));
        tools.add(tool(
                "burp_http_send",
                "Send an HTTP request through Burp (lands in Proxy History when send-via-proxy is on).",
                props(
                        p("raw", "string", "Full raw HTTP request"),
                        p("host", "string", null),
                        p("port", "integer", null),
                        p("https", "boolean", null)),
                List.of("raw")));
        tools.add(tool(
                "burp_sitemap",
                "List Burp site map entries, optional urlPrefix filter.",
                props(p("urlPrefix", "string", null), p("limit", "integer", null)),
                List.of()));
        tools.add(tool("burp_project_info", "Burp project name, version, and exported project options JSON.", obj(), List.of()));
        tools.add(tool("burp_cookies", "List cookies in Burp's cookie jar.", obj(), List.of()));
        tools.add(tool(
                "burp_issues",
                "List Scanner audit issues from the site map (Pro).",
                props(p("urlPrefix", "string", null), p("limit", "integer", null)),
                List.of()));
        tools.add(tool("burp_scan_crawl", "Start a Burp Scanner crawl (Pro).", props(p("url", "string", "Seed URL")), List.of("url")));
        tools.add(tool("burp_scan_audit", "Start a Burp Scanner audit (Pro).", props(p("url", "string", "Seed URL")), List.of("url")));
        tools.add(tool(
                "burp_scan_report",
                "Write a Scanner HTML or XML report to a local path (Pro).",
                props(p("path", "string", "Output file"), p("format", "string", "html or xml")),
                List.of("path")));
        tools.add(tool(
                "burp_collaborator_payload",
                "Generate a Burp Collaborator payload (Pro).",
                props(p("customData", "string", "Optional alphanumeric tag, max 16")),
                List.of()));
        tools.add(tool("burp_collaborator_poll", "Poll Collaborator interactions for this extension client (Pro).", obj(), List.of()));
        tools.add(tool("burp_organizer_list", "List Organizer items.", props(p("limit", "integer", null)), List.of()));
        tools.add(tool(
                "burp_organizer_send",
                "Send a raw HTTP request to Organizer.",
                props(p("raw", "string", null), p("host", "string", null), p("port", "integer", null), p("https", "boolean", null)),
                List.of("raw")));
        tools.add(tool(
                "burp_websocket_history",
                "Read Proxy WebSocket history.",
                props(p("limit", "integer", null), p("contains", "string", null)),
                List.of()));
        tools.add(tool(
                "burp_websocket_send",
                "Open a WebSocket via Burp and send a text frame.",
                props(p("url", "string", "HTTP upgrade URL"), p("text", "string", "Message")),
                List.of("url", "text")));
        tools.add(tool(
                "burp_annotate",
                "Set notes and highlight color on a Proxy history item.",
                props(p("index", "integer", null), p("notes", "string", null), p("color", "string", "RED, ORANGE, ...")),
                List.of("index")));
        tools.add(tool("burp_send_to_comparer", "Send text to Comparer.", props(p("data", "string", null)), List.of("data")));
        tools.add(tool("burp_send_to_decoder", "Send text to Decoder.", props(p("data", "string", null)), List.of("data")));
        tools.add(tool("burp_import_bcheck", "Import a BCheck file (Pro).", props(p("path", "string", null)), List.of("path")));
        tools.add(tool("burp_import_bambda", "Import a Bambda file.", props(p("path", "string", null)), List.of("path")));
        tools.add(tool(
                "burp_analyze_keywords",
                "Keyword analyzer over raw HTTP responses.",
                props(p("keywords", "string", "Comma-separated"), p("responses", "string", "Responses joined by ---")),
                List.of("keywords")));
        tools.add(tool(
                "burp_analyze_variations",
                "Response variations analyzer over raw HTTP responses.",
                props(p("responses", "string", "Responses joined by ---")),
                List.of("responses")));
        tools.add(tool(
                "burp_search",
                "Search Proxy history for a string.",
                props(p("contains", "string", null), p("limit", "integer", null)),
                List.of("contains")));
        tools.add(tool(
                "burp_copy_curl",
                "Convert a raw HTTP request to a curl command.",
                props(p("raw", "string", null), p("url", "string", null), p("https", "boolean", null)),
                List.of("raw")));
        tools.add(tool(
                "burp_finding_draft",
                "Draft a SquidSec-style finding from a request/response pair.",
                props(
                        p("title", "string", "Type - short impact"),
                        p("url", "string", null),
                        p("description", "string", "Starts with Our consultants identified if omitted"),
                        p("raw", "string", "Request"),
                        p("response", "string", "Response"),
                        p("recommendation", "string", null)),
                List.of("title", "url")));
        tools.add(tool(
                "burp_endpoint_map",
                "Deduped method+host+path map. Pass lines as METHOD url.",
                props(p("lines", "string", "One METHOD url per line")),
                List.of("lines")));
        tools.add(tool(
                "burp_csrf_poc",
                "Generate an auto-submit CSRF HTML PoC.",
                props(p("url", "string", null), p("method", "string", null), p("fields", "string", "k=v&k2=v2")),
                List.of("url")));
        tools.add(tool("burp_decode", "URL, Base64, and HTML decode helpers.", props(p("input", "string", null)), List.of("input")));
        tools.add(tool(
                "burp_scope_from_program",
                "Parse bug-bounty program JSON and include discovered http(s) assets in scope.",
                props(p("json", "string", "Program JSON"), p("apply", "boolean", "If true, includeInScope each URL")),
                List.of("json")));
        tools.add(tool(
                "burp_evidence_pack",
                "Write a redacted evidence markdown file from raw request/response.",
                props(p("path", "string", null), p("title", "string", null), p("url", "string", null), p("raw", "string", null), p("response", "string", null)),
                List.of("path")));
        return tools;
    }

    public static Map<String, Object> toolsPayload() {
        Map<String, Object> m = Json.obj();
        m.put("name", "burp-ai-bridge");
        m.put("version", BridgeVersion.VERSION);
        m.put("protocol", "mcp");
        m.put("tools", tools());
        return m;
    }

    public static Map<String, Object> initializeResult(String protocolVersion) {
        Map<String, Object> caps = Json.obj();
        caps.put("tools", Json.obj());
        Map<String, Object> info = Json.obj();
        info.put("name", "burp-ai-bridge");
        info.put("version", BridgeVersion.VERSION);
        Map<String, Object> result = Json.obj();
        result.put("protocolVersion", protocolVersion == null || protocolVersion.isBlank() ? "2025-06-18" : protocolVersion);
        result.put("capabilities", caps);
        result.put("serverInfo", info);
        return result;
    }

    static Map<String, Object> tool(String name, String desc, Map<String, Object> properties, List<String> required) {
        Map<String, Object> schema = Json.obj();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("additionalProperties", false);
        if (required != null && !required.isEmpty()) {
            schema.put("required", new ArrayList<>(required));
        }
        Map<String, Object> t = Json.obj();
        t.put("name", name);
        t.put("description", desc);
        t.put("inputSchema", schema);
        return t;
    }

    @SafeVarargs
    static Map<String, Object> props(Map<String, Object>... entries) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (Map<String, Object> e : entries) {
            m.putAll(e);
        }
        return m;
    }

    static Map<String, Object> p(String name, String type, String description) {
        Map<String, Object> field = Json.obj();
        field.put("type", type);
        if (description != null && !description.isBlank()) {
            field.put("description", description);
        }
        Map<String, Object> wrap = new LinkedHashMap<>();
        wrap.put(name, field);
        return wrap;
    }

    static Map<String, Object> obj() {
        return new LinkedHashMap<>();
    }
}
