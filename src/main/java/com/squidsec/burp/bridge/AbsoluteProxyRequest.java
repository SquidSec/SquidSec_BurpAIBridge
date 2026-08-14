package com.squidsec.burp.bridge;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Rewrites a target request so Burp's HTTP engine delivers it to the local
 * proxy listener (absolute-form request line). That puts the exchange in
 * Proxy History and the saved project.
 */
public final class AbsoluteProxyRequest {

    private AbsoluteProxyRequest() {}

    public static String rewriteRaw(String method, String targetUrl, String originalRaw) {
        String raw = originalRaw == null ? "" : originalRaw;
        if (raw.startsWith("\uFEFF")) {
            raw = raw.substring(1);
        }
        raw = raw.replace("\r\n", "\n").replace("\n", "\r\n");
        int firstNl = raw.indexOf("\r\n");
        String requestLine = firstNl >= 0 ? raw.substring(0, firstNl) : raw;
        String rest = firstNl >= 0 ? raw.substring(firstNl) : "\r\n\r\n";
        String version = "HTTP/1.1";
        int lastSp = requestLine.lastIndexOf(' ');
        if (lastSp > 0 && requestLine.substring(lastSp + 1).startsWith("HTTP/")) {
            version = requestLine.substring(lastSp + 1);
        }
        String m = method == null || method.isBlank() ? "GET" : method;
        String url = targetUrl == null ? "/" : targetUrl;
        return m + " " + url + " " + version + rest;
    }

    public static HttpRequest wrap(HttpRequest req, String proxyHost, int proxyPort) {
        String raw = MessageCodec.requestRaw(req, true, Integer.MAX_VALUE);
        String rewritten = rewriteRaw(req.method(), req.url(), raw);
        HttpService proxy = HttpService.httpService(proxyHost, proxyPort, false);
        return HttpRequest.httpRequest(proxy, rewritten);
    }
}
