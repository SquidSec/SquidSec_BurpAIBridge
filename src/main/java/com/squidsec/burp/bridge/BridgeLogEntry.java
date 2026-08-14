package com.squidsec.burp.bridge;

import java.time.Instant;

/**
 * One target HTTP exchange shown in the AI Bridge history tab (proxy-history style).
 * Bridge control-plane API calls are not logged here.
 */
public final class BridgeLogEntry {

    private final long id;
    private final Instant time;
    private final String client;
    private final String method;
    private final String path;
    private final String query;
    private final String url;
    private final String host;
    private final int port;
    private final boolean https;
    private final int status;
    private final long durationMs;
    private final String requestRaw;
    private final String responseRaw;

    public BridgeLogEntry(
            long id,
            Instant time,
            String client,
            String method,
            String path,
            String query,
            String url,
            String host,
            int port,
            boolean https,
            int status,
            long durationMs,
            String requestRaw,
            String responseRaw) {
        this.id = id;
        this.time = time;
        this.client = client == null ? "" : client;
        this.method = method == null ? "" : method;
        this.path = path == null ? "/" : path;
        this.query = query == null ? "" : query;
        this.url = url == null ? "" : url;
        this.host = host == null ? "" : host;
        this.port = port;
        this.https = https;
        this.status = status;
        this.durationMs = durationMs;
        this.requestRaw = requestRaw == null ? "" : requestRaw;
        this.responseRaw = responseRaw == null ? "" : responseRaw;
    }

    public long id() {
        return id;
    }

    public Instant time() {
        return time;
    }

    public String client() {
        return client;
    }

    public String method() {
        return method;
    }

    public String path() {
        return path;
    }

    public String query() {
        return query;
    }

    public String pathWithQuery() {
        if (query == null || query.isBlank()) {
            return path;
        }
        return path + "?" + query;
    }

    /** Full target URL when known; otherwise pathWithQuery. */
    public String displayUrl() {
        if (url != null && !url.isBlank()) {
            return url;
        }
        return pathWithQuery();
    }

    public String host() {
        return host;
    }

    public int port() {
        return port;
    }

    public boolean https() {
        return https;
    }

    public int status() {
        return status;
    }

    public long durationMs() {
        return durationMs;
    }

    public String requestRaw() {
        return requestRaw;
    }

    public String responseRaw() {
        return responseRaw;
    }

    public boolean targetTraffic() {
        return true;
    }

    public String targetHost() {
        return host;
    }

    public int targetPort() {
        return port;
    }

    public boolean targetHttps() {
        return https;
    }

    public int responseLength() {
        return responseRaw == null ? 0 : responseRaw.length();
    }

    /** Body-only length estimate (after headers) for Length column. */
    public int responseBodyLength() {
        if (responseRaw == null || responseRaw.isEmpty()) {
            return 0;
        }
        int idx = responseRaw.indexOf("\r\n\r\n");
        if (idx >= 0) {
            return responseRaw.length() - idx - 4;
        }
        idx = responseRaw.indexOf("\n\n");
        if (idx >= 0) {
            return responseRaw.length() - idx - 2;
        }
        return responseRaw.length();
    }
}
