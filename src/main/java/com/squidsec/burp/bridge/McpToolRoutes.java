package com.squidsec.burp.bridge;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Maps MCP tool names to the existing HTTP API routes. */
public final class McpToolRoutes {

    public static final class Mapped {
        public final String method;
        public final String path;
        public final Map<String, String> query;
        public final byte[] body;

        Mapped(String method, String path, Map<String, String> query, byte[] body) {
            this.method = method;
            this.path = path;
            this.query = query == null ? new LinkedHashMap<>() : query;
            this.body = body == null ? new byte[0] : body;
        }
    }

    private McpToolRoutes() {}

    public static Mapped map(String name, Map<String, Object> args) {
        Map<String, Object> a = args == null ? Map.of() : args;
        return switch (name == null ? "" : name) {
            case "burp_bridge_health" -> get("/health");
            case "burp_scope_check" -> get("/scope/check", q("url", str(a, "url")));
            case "burp_scope_include" -> post("/scope/include", a);
            case "burp_scope_exclude" -> post("/scope/exclude", a);
            case "burp_proxy_intercept_get" -> get("/proxy/intercept");
            case "burp_proxy_intercept_set" -> post("/proxy/intercept", a);
            case "burp_proxy_history" -> get("/proxy/history", historyQuery(a));
            case "burp_proxy_history_item" -> get("/proxy/history/item", itemQuery(a));
            case "burp_rewrite_list" -> get("/rewrite/rules");
            case "burp_rewrite_add" -> post("/rewrite/rules", a);
            case "burp_rewrite_delete" -> post("/rewrite/rules/delete", a);
            case "burp_rewrite_clear" -> post("/rewrite/rules/clear", Map.of());
            case "burp_send_to_repeater" -> post("/repeater", a);
            case "burp_send_to_intruder" -> post("/intruder", a);
            case "burp_http_send" -> post("/http/send", a);
            case "burp_sitemap" -> get("/sitemap", q("urlPrefix", str(a, "urlPrefix"), "limit", str(a, "limit")));
            case "burp_project_info" -> get("/project");
            case "burp_cookies" -> get("/cookies");
            case "burp_issues" -> get("/scanner/issues", q("urlPrefix", str(a, "urlPrefix"), "limit", str(a, "limit")));
            case "burp_scan_crawl" -> post("/scanner/crawl", a);
            case "burp_scan_audit" -> post("/scanner/audit", a);
            case "burp_scan_report" -> post("/scanner/report", a);
            case "burp_collaborator_payload" -> post("/collaborator/payload", a);
            case "burp_collaborator_poll" -> get("/collaborator/poll");
            case "burp_organizer_list" -> get("/organizer", q("limit", str(a, "limit")));
            case "burp_organizer_send" -> post("/organizer", a);
            case "burp_websocket_history" ->
                    get("/websocket/history", q("limit", str(a, "limit"), "contains", str(a, "contains")));
            case "burp_websocket_send" -> post("/websocket/send", a);
            case "burp_annotate" -> post("/proxy/annotate", a);
            case "burp_send_to_comparer" -> post("/comparer", a);
            case "burp_send_to_decoder" -> post("/decoder", a);
            case "burp_import_bcheck" -> post("/import/bcheck", a);
            case "burp_import_bambda" -> post("/import/bambda", a);
            case "burp_analyze_keywords" -> post("/analyze/keywords", a);
            case "burp_analyze_variations" -> post("/analyze/variations", a);
            case "burp_search" -> get("/search", q("contains", str(a, "contains"), "limit", str(a, "limit")));
            case "burp_copy_curl" -> post("/tools/curl", a);
            case "burp_finding_draft" -> post("/tools/finding", a);
            case "burp_endpoint_map" -> post("/tools/endpoints", a);
            case "burp_csrf_poc" -> post("/tools/csrf", a);
            case "burp_decode" -> post("/tools/decode", a);
            case "burp_scope_from_program" -> post("/scope/from-program", a);
            case "burp_evidence_pack" -> post("/tools/evidence", a);
            default -> null;
        };
    }

    private static Mapped get(String path) {
        return new Mapped("GET", path, new LinkedHashMap<>(), new byte[0]);
    }

    private static Mapped get(String path, Map<String, String> query) {
        return new Mapped("GET", path, query, new byte[0]);
    }

    private static Mapped post(String path, Map<String, Object> body) {
        byte[] raw = Json.stringify(body == null ? Map.of() : body).getBytes(StandardCharsets.UTF_8);
        return new Mapped("POST", path, new LinkedHashMap<>(), raw);
    }

    private static Map<String, String> historyQuery(Map<String, Object> a) {
        Map<String, String> q = q(
                "offset", str(a, "offset"),
                "limit", str(a, "limit"),
                "host", str(a, "host"),
                "method", str(a, "method"),
                "status", str(a, "status"),
                "contains", str(a, "contains"),
                "urlContains", str(a, "urlContains"),
                "includeBody", str(a, "includeBody"),
                "bodyLimit", str(a, "bodyLimit"),
                "format", str(a, "format"));
        if (a.containsKey("inScopeOnly")) {
            q.put("inScopeOnly", str(a, "inScopeOnly"));
        } else if (a.containsKey("inScope")) {
            q.put("inScopeOnly", str(a, "inScope"));
        }
        return q;
    }

    private static Map<String, String> itemQuery(Map<String, Object> a) {
        return q(
                "index", str(a, "index"),
                "id", str(a, "id"),
                "includeBody", str(a, "includeBody"),
                "bodyLimit", str(a, "bodyLimit"),
                "format", str(a, "format"));
    }

    private static Map<String, String> q(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] != null && !kv[i + 1].isBlank()) {
                m.put(kv[i], kv[i + 1]);
            }
        }
        return m;
    }

    private static String str(Map<String, Object> a, String key) {
        Object v = a.get(key);
        return v == null ? null : String.valueOf(v);
    }
}
