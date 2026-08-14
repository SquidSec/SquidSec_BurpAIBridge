package com.squidsec.burp.bridge;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pure helpers: curl, findings, endpoint map, CSRF PoC, decode, program-scope. */
public final class EngagementTools {

    private static final Pattern PATH_ID = Pattern.compile("/(\\d{2,}|[0-9a-fA-F-]{8,})(?=/|$)");

    private EngagementTools() {}

    public static String toCurl(String rawRequest, String url, boolean https) {
        if (rawRequest == null || rawRequest.isBlank()) {
            return "";
        }
        String raw = rawRequest.replace("\r\n", "\n");
        String[] parts = raw.split("\n\n", 2);
        String[] lines = parts[0].split("\n");
        if (lines.length == 0) {
            return "";
        }
        String[] rl = lines[0].split(" ", 3);
        String method = rl.length > 0 ? rl[0] : "GET";
        String path = rl.length > 1 ? rl[1] : "/";
        String target = url;
        if (target == null || target.isBlank()) {
            String host = header(lines, "Host");
            String scheme = https ? "https" : "http";
            target = scheme + "://" + (host == null ? "localhost" : host) + (path.startsWith("http") ? "" : path);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("curl -sk");
        if (!"GET".equalsIgnoreCase(method)) {
            sb.append(" -X ").append(shell(method));
        }
        sb.append(" ").append(shell(target));
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c <= 0) {
                continue;
            }
            String name = lines[i].substring(0, c).trim();
            String value = lines[i].substring(c + 1).trim();
            if (name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase("Host")) {
                continue;
            }
            sb.append(" -H ").append(shell(name + ": " + value));
        }
        if (parts.length > 1 && !parts[1].isBlank()) {
            sb.append(" --data-binary ").append(shell(parts[1]));
        }
        return sb.toString();
    }

    public static String findingDraft(
            String title, String url, String description, String requestRaw, String responseRaw, String recommendation) {
        String t = title == null || title.isBlank() ? "Issue - impact TBD" : title.trim();
        String u = url == null ? "" : url.trim();
        String desc = description == null || description.isBlank()
                ? "Our consultants identified an issue that requires confirmation."
                : description.trim();
        if (!desc.startsWith("Our consultants identified")) {
            desc = "Our consultants identified " + desc;
        }
        String rec = recommendation == null || recommendation.isBlank()
                ? "Confirm impact, restrict access, and retest after the fix."
                : recommendation.trim();
        StringBuilder sb = new StringBuilder();
        sb.append(t).append("\n\n");
        sb.append("### URL\n\n`").append(u).append("`\n\n");
        sb.append("### Description\n\n").append(desc).append("\n\n");
        sb.append("### Steps to Replicate\n\n");
        sb.append("1. Send the request below through Burp (Repeater or AI Bridge /http/send).\n");
        sb.append("2. Compare the response to an unauthenticated or lower-privilege control.\n\n");
        sb.append("### Request and Response\n\nProof pair\n\n");
        sb.append("```\n").append(redact(requestRaw)).append("\n```\n\n");
        sb.append("```\n").append(redact(responseRaw)).append("\n```\n\n");
        sb.append("### Recommendation\n\n").append(rec).append('\n');
        return sb.toString();
    }

    public static String redact(String raw) {
        if (raw == null) {
            return "";
        }
        String out = raw;
        out = out.replaceAll("(?im)^(Authorization|Cookie|Set-Cookie|X-CSRF-Token|X-XSRF-TOKEN):.*$", "$1: [REDACTED]");
        out = out.replaceAll("(?i)(bearer\\s+)[A-Za-z0-9._\\-+=/]+", "$1[REDACTED]");
        out = out.replaceAll(
                "(?i)(api[_-]?key|password|secret|token|access_token|refresh_token)\\s*[:=]\\s*[^\\s&\"']+",
                "$1=[REDACTED]");
        return out;
    }

    public static List<Map<String, Object>> endpointMap(List<String> methodUrlPairs) {
        Map<String, Map<String, Object>> byKey = new LinkedHashMap<>();
        if (methodUrlPairs == null) {
            return new ArrayList<>();
        }
        for (String line : methodUrlPairs) {
            if (line == null || line.isBlank()) {
                continue;
            }
            String method = "GET";
            String url = line.trim();
            int sp = url.indexOf(' ');
            if (sp > 0 && sp < 12) {
                method = url.substring(0, sp).toUpperCase(Locale.ROOT);
                url = url.substring(sp + 1).trim();
            }
            final String methodF = method;
            final String urlF = url;
            String path = pathOf(urlF);
            String host = hostOf(urlF);
            String pattern = PATH_ID.matcher(path).replaceAll("/{id}");
            String key = methodF + " " + host + " " + pattern;
            Map<String, Object> row = byKey.computeIfAbsent(key, k -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("method", methodF);
                m.put("host", host);
                m.put("pattern", pattern);
                m.put("count", 0);
                m.put("examples", new ArrayList<String>());
                return m;
            });
            row.put("count", ((Number) row.get("count")).intValue() + 1);
            @SuppressWarnings("unchecked")
            List<String> ex = (List<String>) row.get("examples");
            if (ex.size() < 3 && !ex.contains(urlF)) {
                ex.add(urlF);
            }
        }
        return new ArrayList<>(byKey.values());
    }

    public static String csrfPoc(String url, String method, Map<String, String> fields) {
        String m = method == null || method.isBlank() ? "POST" : method.toUpperCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body>\n");
        sb.append("<form id=\"f\" method=\"").append(esc(m)).append("\" action=\"").append(esc(url)).append("\">\n");
        if (fields != null) {
            for (Map.Entry<String, String> e : fields.entrySet()) {
                sb.append("<input type=\"hidden\" name=\"")
                        .append(esc(e.getKey()))
                        .append("\" value=\"")
                        .append(esc(e.getValue() == null ? "" : e.getValue()))
                        .append("\">\n");
            }
        }
        sb.append("</form>\n<script>document.getElementById('f').submit()</script>\n");
        sb.append("</body></html>\n");
        return sb.toString();
    }

    public static Map<String, Object> decodeAll(String input) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (input == null) {
            input = "";
        }
        m.put("input", input);
        try {
            m.put("urlDecoded", java.net.URLDecoder.decode(input, StandardCharsets.UTF_8));
        } catch (Exception e) {
            m.put("urlDecoded", null);
        }
        try {
            m.put("base64", new String(Base64.getDecoder().decode(input.replaceAll("\\s", "")), StandardCharsets.UTF_8));
        } catch (Exception e) {
            m.put("base64", null);
        }
        m.put("htmlUnescaped", input.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", "\""));
        return m;
    }

    public static List<String> scopeUrlsFromProgramJson(String json) {
        Set<String> urls = new LinkedHashSet<>();
        if (json == null || json.isBlank()) {
            return new ArrayList<>();
        }
        Object parsed = Json.parse(json);
        collectUrls(parsed, urls);
        return new ArrayList<>(urls);
    }

    private static void collectUrls(Object o, Set<String> urls) {
        if (o instanceof String s) {
            String t = s.trim();
            if (t.startsWith("http://") || t.startsWith("https://") || t.startsWith("*.")) {
                urls.add(normalizeAsset(t));
            }
            return;
        }
        if (o instanceof List<?> list) {
            for (Object i : list) {
                collectUrls(i, urls);
            }
            return;
        }
        if (o instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String k = String.valueOf(e.getKey()).toLowerCase(Locale.ROOT);
                Object v = e.getValue();
                if (v instanceof String s
                        && (k.contains("url")
                                || k.contains("asset")
                                || k.equals("identifier")
                                || k.equals("endpoint")
                                || k.equals("target"))) {
                    String t = s.trim();
                    if (t.startsWith("http") || t.startsWith("*.") || t.contains(".")) {
                        urls.add(normalizeAsset(t));
                    }
                }
                collectUrls(v, urls);
            }
        }
    }

    static String normalizeAsset(String raw) {
        String t = raw.trim();
        if (t.startsWith("*.")) {
            return "https://" + t.substring(2) + "/";
        }
        if (!t.startsWith("http")) {
            t = "https://" + t;
        }
        int hostStart = t.indexOf("://") + 3;
        if (hostStart > 2 && t.indexOf('/', hostStart) < 0) {
            t = t + "/";
        }
        return t;
    }

    static String pathOf(String url) {
        try {
            String p = URI.create(url).getRawPath();
            return p == null || p.isBlank() ? "/" : p;
        } catch (Exception e) {
            return url;
        }
    }

    static String hostOf(String url) {
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (Exception e) {
            return "";
        }
    }

    private static String header(String[] lines, String name) {
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0 && lines[i].substring(0, c).trim().equalsIgnoreCase(name)) {
                return lines[i].substring(c + 1).trim();
            }
        }
        return null;
    }

    private static String shell(String s) {
        return "'" + s.replace("'", "'\"'\"'") + "'";
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }
}
