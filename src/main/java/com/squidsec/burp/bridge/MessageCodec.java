package com.squidsec.burp.bridge;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Encode Burp HTTP messages for the AI bridge API.
 *
 * <p>{@code format=http} (default for history list) returns Burp-style raw request/response
 * strings. {@code format=json} returns structured fields. Bodies are omitted when
 * {@code includeBody=false}; binary bodies are never dumped as mojibake.
 */
public final class MessageCodec {

    private MessageCodec() {}

    public static Map<String, Object> requestToJson(HttpRequest req, boolean includeBody, int bodyLimit) {
        Map<String, Object> m = Json.obj();
        if (req == null) {
            return m;
        }
        try {
            m.put("method", req.method());
            m.put("path", req.path());
            m.put("url", req.url());
            m.put("httpVersion", req.httpVersion());
            HttpService svc = req.httpService();
            if (svc != null) {
                Map<String, Object> service = Json.obj();
                service.put("host", svc.host());
                service.put("port", svc.port());
                service.put("secure", svc.secure());
                m.put("service", service);
            }
            m.put("headers", headersToJson(req.headers()));
            BodyView body = bodyView(req.body().getBytes(), contentType(req.headers()), includeBody, bodyLimit);
            if (includeBody) {
                m.put("body", body.text);
                m.put("bodyTruncated", body.truncated);
                m.put("bodyBinary", body.binary);
                m.put("bodyLength", body.length);
            }
            m.put("raw", requestRaw(req, includeBody, bodyLimit));
        } catch (Exception e) {
            m.put("error", e.getMessage());
        }
        return m;
    }

    public static Map<String, Object> responseToJson(HttpResponse resp, boolean includeBody, int bodyLimit) {
        Map<String, Object> m = Json.obj();
        if (resp == null) {
            m.put("present", false);
            return m;
        }
        m.put("present", true);
        try {
            m.put("statusCode", resp.statusCode());
            m.put("reasonPhrase", resp.reasonPhrase());
            m.put("httpVersion", resp.httpVersion());
            m.put("headers", headersToJson(resp.headers()));
            BodyView body = bodyView(resp.body().getBytes(), contentType(resp.headers()), includeBody, bodyLimit);
            if (includeBody) {
                m.put("body", body.text);
                m.put("bodyTruncated", body.truncated);
                m.put("bodyBinary", body.binary);
                m.put("bodyLength", body.length);
            }
            m.put("raw", responseRaw(resp, includeBody, bodyLimit));
        } catch (Exception e) {
            m.put("error", e.getMessage());
        }
        return m;
    }

    /**
     * @param format {@code http} (Burp-style raw strings) or {@code json} (structured)
     */
    public static Map<String, Object> historyItemToJson(
            ProxyHttpRequestResponse item,
            int index,
            boolean includeBody,
            int bodyLimit,
            boolean inScope,
            String format) {
        Map<String, Object> m = Json.obj();
        m.put("index", index);
        try {
            HttpRequest req = item.finalRequest();
            HttpResponse resp = item.response();
            String url = "";
            try {
                url = req != null ? req.url() : "";
            } catch (Exception ignored) {
            }
            m.put("url", url);
            m.put("inScope", inScope);
            if (req != null) {
                m.put("method", req.method());
            }
            if (resp != null) {
                m.put("status", (int) resp.statusCode());
            } else {
                m.put("status", null);
            }
            if (item.annotations() != null) {
                m.put("notes", item.annotations().notes());
                if (item.annotations().hasHighlightColor() && item.annotations().highlightColor() != null) {
                    m.put("highlight", item.annotations().highlightColor().name());
                }
            }
            m.put("edited", item.edited());
            m.put("time", item.time() == null ? null : item.time().toString());
            m.put("listenerPort", item.listenerPort());

            if ("json".equalsIgnoreCase(format)) {
                m.put("request", requestToJson(req, includeBody, bodyLimit));
                m.put("response", responseToJson(resp, includeBody, bodyLimit));
            } else {
                // default: Burp-style raw HTTP messages as strings
                m.put("request", requestRaw(req, includeBody, bodyLimit));
                m.put("response", responseRaw(resp, includeBody, bodyLimit));
            }
        } catch (Exception e) {
            m.put("error", e.getMessage());
        }
        return m;
    }

    public static String requestRaw(HttpRequest req, boolean includeBody, int bodyLimit) {
        if (req == null) {
            return "";
        }
        try {
            String headersOnly = headersBlock(req.toString());
            if (!includeBody) {
                return headersOnly;
            }
            byte[] body = req.body().getBytes();
            return headersOnly + bodySuffix(body, contentType(req.headers()), bodyLimit);
        } catch (Exception e) {
            return "";
        }
    }

    public static String responseRaw(HttpResponse resp, boolean includeBody, int bodyLimit) {
        if (resp == null) {
            return "";
        }
        try {
            String headersOnly = headersBlock(resp.toString());
            if (!includeBody) {
                return headersOnly;
            }
            byte[] body = resp.body().getBytes();
            return headersOnly + bodySuffix(body, contentType(resp.headers()), bodyLimit);
        } catch (Exception e) {
            return "";
        }
    }

    public static HttpRequest buildRequest(Map<String, Object> body) {
        String raw = Json.str(body, "raw");
        if (raw == null || raw.isBlank()) {
            raw = Json.str(body, "request");
        }
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("raw/request HTTP message is required");
        }
        raw = raw.replace("\r\n", "\n").replace("\n", "\r\n");

        String host = Json.str(body, "host");
        int port = Json.integer(body, "port", -1);
        boolean https = Json.bool(body, "https", true);

        if (host != null && !host.isBlank() && port > 0) {
            HttpService service = HttpService.httpService(host, port, https);
            return HttpRequest.httpRequest(service, raw);
        }
        HttpRequest req = HttpRequest.httpRequest(raw);
        if (host != null && !host.isBlank()) {
            if (port <= 0) {
                port = https ? 443 : 80;
            }
            return req.withService(HttpService.httpService(host, port, https));
        }
        return req;
    }

    /** Keep status line + headers + trailing blank line; drop body. */
    static String headersBlock(String fullMessage) {
        if (fullMessage == null) {
            return "";
        }
        String normalized = fullMessage.replace("\r\n", "\n").replace('\r', '\n');
        int idx = normalized.indexOf("\n\n");
        String head = idx >= 0 ? normalized.substring(0, idx) : normalized;
        return head.replace("\n", "\r\n") + "\r\n\r\n";
    }

    private static String bodySuffix(byte[] body, String contentType, int bodyLimit) {
        BodyView view = bodyView(body, contentType, true, bodyLimit);
        if (view.binary) {
            return "[binary " + safeType(contentType) + ", " + view.length + " bytes omitted]\r\n";
        }
        if (view.text == null) {
            return "";
        }
        String text = view.text;
        if (view.truncated) {
            return text + "\r\n…[truncated, " + view.length + " bytes total]\r\n";
        }
        return text;
    }

    private static BodyView bodyView(byte[] body, String contentType, boolean includeBody, int bodyLimit) {
        BodyView v = new BodyView();
        if (body == null) {
            v.length = 0;
            v.text = "";
            return v;
        }
        v.length = body.length;
        if (!includeBody) {
            return v;
        }
        if (isBinary(contentType, body)) {
            v.binary = true;
            v.text = "[binary " + safeType(contentType) + ", " + body.length + " bytes omitted]";
            return v;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        if (bodyLimit > 0 && text.length() > bodyLimit) {
            v.truncated = true;
            v.text = text.substring(0, bodyLimit);
        } else {
            v.text = text;
        }
        return v;
    }

    private static boolean isBinary(String contentType, byte[] body) {
        if (contentType != null) {
            String ct = contentType.toLowerCase(Locale.ROOT);
            int semi = ct.indexOf(';');
            if (semi >= 0) {
                ct = ct.substring(0, semi).trim();
            }
            if (ct.startsWith("image/")
                    || ct.startsWith("audio/")
                    || ct.startsWith("video/")
                    || ct.equals("application/octet-stream")
                    || ct.equals("application/pdf")
                    || ct.equals("application/zip")
                    || ct.equals("application/gzip")
                    || ct.equals("application/x-gzip")
                    || ct.equals("application/x-7z-compressed")
                    || ct.equals("application/x-rar-compressed")
                    || ct.contains("font/")
                    || ct.endsWith("+zip")
                    || ct.equals("application/wasm")
                    || ct.equals("application/x-protobuf")
                    || ct.equals("application/grpc")
                    || ct.equals("application/x-msdownload")) {
                return true;
            }
            if (ct.startsWith("text/")
                    || ct.contains("json")
                    || ct.contains("xml")
                    || ct.contains("javascript")
                    || ct.contains("urlencoded")
                    || ct.startsWith("multipart/")) {
                return false;
            }
        }
        return looksBinary(body);
    }

    private static boolean looksBinary(byte[] body) {
        if (body == null || body.length == 0) {
            return false;
        }
        int sample = Math.min(body.length, 512);
        int suspicious = 0;
        for (int i = 0; i < sample; i++) {
            int b = body[i] & 0xff;
            if (b == 0) {
                return true;
            }
            if (b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f) {
                suspicious++;
            }
        }
        return suspicious * 10 > sample;
    }

    private static String contentType(List<HttpHeader> headers) {
        if (headers == null) {
            return null;
        }
        for (HttpHeader h : headers) {
            if (h.name() != null && h.name().equalsIgnoreCase("Content-Type")) {
                return h.value();
            }
        }
        return null;
    }

    private static String safeType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return "unknown";
        }
        int semi = contentType.indexOf(';');
        return semi >= 0 ? contentType.substring(0, semi).trim() : contentType.trim();
    }

    private static List<Object> headersToJson(List<HttpHeader> headers) {
        List<Object> list = Json.arr();
        if (headers == null) {
            return list;
        }
        for (HttpHeader h : headers) {
            Map<String, Object> item = Json.obj();
            item.put("name", h.name());
            item.put("value", h.value());
            list.add(item);
        }
        return list;
    }

    private static final class BodyView {
        String text;
        boolean truncated;
        boolean binary;
        int length;
    }
}
