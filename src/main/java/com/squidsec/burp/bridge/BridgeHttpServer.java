package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Loopback JSON HTTP API for Grok / automation.
 *
 * Uses {@link ServerSocket} only — Burp's JRE does not ship {@code jdk.httpserver}
 * ({@code com.sun.net.httpserver.HttpServer}).
 */
public final class BridgeHttpServer {

    private static final int PORT_SEARCH_RANGE = 20;

    private final MontoyaApi api;
    private volatile BridgeConfig config;
    private final RewriteEngine rewriteEngine;
    private final BridgeHistoryLog historyLog;
    private final BurpTools burpTools;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private ServerSocket serverSocket;
    private ExecutorService acceptPool;
    private ExecutorService workerPool;
    private int boundPort = -1;

    /** Per-request logging context (worker threads). */
    private final ThreadLocal<LogCtx> logCtx = new ThreadLocal<>();

    private static final class LogCtx {
        final Request request;
        final String client;
        final long startedMs;
        /** When set, a proxy-history style row is recorded for target traffic. */
        boolean hasTarget;
        String viewRequestRaw;
        String viewResponseRaw;
        String viewMethod;
        String viewPath;
        String viewQuery;
        String viewUrl;
        String viewHost;
        int viewPort;
        boolean viewHttps;
        Integer viewStatus;

        LogCtx(Request request, String client, long startedMs) {
            this.request = request;
            this.client = client;
            this.startedMs = startedMs;
        }

        void setTargetView(HttpRequest req, HttpResponse resp, int bodyLimit) {
            hasTarget = req != null;
            if (req != null) {
                viewRequestRaw = MessageCodec.requestRaw(req, true, bodyLimit);
                viewMethod = req.method();
                viewPath = "/";
                viewQuery = "";
                try {
                    String full = req.path();
                    if (full == null || full.isBlank()) {
                        full = "/";
                    }
                    int q = full.indexOf('?');
                    if (q >= 0) {
                        viewPath = full.substring(0, q);
                        viewQuery = full.substring(q + 1);
                    } else {
                        viewPath = full;
                    }
                } catch (Exception ignored) {
                }
                try {
                    viewUrl = req.url();
                } catch (Exception e) {
                    viewUrl = "";
                }
                if (req.httpService() != null) {
                    viewHost = req.httpService().host();
                    viewPort = req.httpService().port();
                    viewHttps = req.httpService().secure();
                }
            }
            if (resp != null) {
                viewResponseRaw = MessageCodec.responseRaw(resp, true, bodyLimit);
                viewStatus = (int) resp.statusCode();
            } else if (viewResponseRaw == null) {
                viewResponseRaw = "";
            }
        }
    }

    public BridgeHttpServer(MontoyaApi api, BridgeConfig config, RewriteEngine rewriteEngine) {
        this(api, config, rewriteEngine, null);
    }

    public BridgeHttpServer(
            MontoyaApi api, BridgeConfig config, RewriteEngine rewriteEngine, BridgeHistoryLog historyLog) {
        this.api = api;
        this.config = config;
        this.rewriteEngine = rewriteEngine;
        this.historyLog = historyLog;
        this.burpTools = new BurpTools(api);
    }

    public BridgeConfig config() {
        return config;
    }

    public synchronized void restart(BridgeConfig newConfig) throws IOException {
        stop();
        this.config = newConfig;
        start();
    }

    /** Actual port after {@link #start()} (may differ from preferred if that port was busy). */
    public int boundPort() {
        return boundPort > 0 ? boundPort : config.port();
    }

    public void start() throws IOException {
        if (running.get()) {
            return;
        }
        InetAddress bind = InetAddress.getByName(config.bindHost());
        int preferred = config.port();
        if (preferred <= 0 || preferred > 65535) {
            preferred = 9877;
        }

        IOException lastBindError = null;
        int max = Math.min(preferred + PORT_SEARCH_RANGE - 1, 65535);
        for (int port = preferred; port <= max; port++) {
            try {
                serverSocket = new ServerSocket(port, 50, bind);
                boundPort = port;
                if (port != preferred) {
                    api.logging()
                            .logToOutput(
                                    "AI Bridge: port "
                                            + preferred
                                            + " already in use; bound to "
                                            + port
                                            + " instead");
                }
                break;
            } catch (java.net.BindException e) {
                lastBindError = e;
            }
        }
        if (serverSocket == null) {
            throw new IOException(
                    "Address already in use: no free port in "
                            + preferred
                            + "-"
                            + max
                            + " on "
                            + config.bindHost()
                            + (lastBindError == null ? "" : " (" + lastBindError.getMessage() + ")"),
                    lastBindError);
        }
        running.set(true);

        acceptPool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "squidsec-bridge-accept");
            t.setDaemon(true);
            return t;
        });
        workerPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "squidsec-bridge-worker");
            t.setDaemon(true);
            return t;
        });

        acceptPool.execute(this::acceptLoop);
    }

    public void stop() {
        running.set(false);
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
            serverSocket = null;
        }
        shutdownPool(acceptPool);
        shutdownPool(workerPool);
        acceptPool = null;
        workerPool = null;
    }

    private static void shutdownPool(ExecutorService pool) {
        if (pool == null) {
            return;
        }
        pool.shutdownNow();
        try {
            pool.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                Socket socket = serverSocket.accept();
                workerPool.execute(() -> handleSocket(socket));
            } catch (SocketException e) {
                if (running.get()) {
                    api.logging().logToError("AI Bridge accept error: " + e.getMessage());
                }
                break;
            } catch (IOException e) {
                if (running.get()) {
                    api.logging().logToError("AI Bridge accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handleSocket(Socket socket) {
        try (socket) {
            socket.setSoTimeout(60_000);
            String client = "unknown";
            try {
                if (socket.getInetAddress() != null) {
                    client = socket.getInetAddress().getHostAddress();
                }
            } catch (Exception ignored) {
            }
            Request req = Request.read(socket.getInputStream());
            if (req == null) {
                return;
            }
            handle(req, socket.getOutputStream(), client);
        } catch (Exception e) {
            api.logging().logToError("AI Bridge request error: " + e.getMessage());
        }
    }

    private void handle(Request ex, OutputStream out, String client) throws IOException {
        long started = System.currentTimeMillis();
        try {
            String path = ex.path;
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (path.length() > 1 && path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            ex = ex.withPath(path);
            logCtx.set(new LogCtx(ex, client, started));

            if ("OPTIONS".equalsIgnoreCase(ex.method)) {
                write(out, 204, "");
                return;
            }

            if ("/health".equals(path) && "GET".equalsIgnoreCase(ex.method)) {
                Map<String, Object> body = Json.obj();
                body.put("ok", true);
                body.put("name", "SquidSec Burp AI Bridge");
                body.put("version", BridgeVersion.VERSION);
                body.put("interceptEnabled", api.proxy().isInterceptEnabled());
                writeJson(out, 200, body);
                return;
            }

            if ("/".equals(path) && "GET".equalsIgnoreCase(ex.method)) {
                writeJson(out, 200, apiDocs());
                return;
            }

            if (isMcpDiscover(path, ex.method)) {
                writeJson(out, 200, McpCatalog.toolsPayload());
                return;
            }

            boolean authorized = authorize(ex);
            if ("/mcp".equals(path) && "POST".equalsIgnoreCase(ex.method)) {
                mcpJsonRpc(ex, out, authorized);
                return;
            }
            if ("/mcp/call".equals(path) && "POST".equalsIgnoreCase(ex.method)) {
                if (!authorized) {
                    writeUnauthorized(out);
                    return;
                }
                mcpCallHttp(ex, out);
                return;
            }

            if (!authorized) {
                writeUnauthorized(out);
                return;
            }

            route(ex, out);
        } catch (Exception e) {
            Map<String, Object> err = Json.obj();
            err.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            writeJson(out, 500, err);
            api.logging().logToError("AI Bridge error: " + e.getMessage());
        } finally {
            logCtx.remove();
        }
    }

    private static boolean isMcpDiscover(String path, String method) {
        if (!"GET".equalsIgnoreCase(method)) {
            return false;
        }
        return "/mcp".equals(path) || "/mcp/tools".equals(path) || "/mcp/list".equals(path);
    }

    private void writeUnauthorized(OutputStream out) throws IOException {
        Map<String, Object> err = Json.obj();
        err.put("error", "unauthorized");
        err.put("hint", "Send header Authorization: Bearer <token> or X-API-Key: <token>");
        writeJson(out, 401, err);
    }

    private void mcpJsonRpc(Request ex, OutputStream out, boolean authorized) throws IOException {
        Object parsed = Json.parse(ex.body == null ? "{}" : new String(ex.body, StandardCharsets.UTF_8));
        if (parsed instanceof List<?> batch) {
            List<Object> replies = Json.arr();
            for (Object item : batch) {
                if (item instanceof Map<?, ?>) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> msg = (Map<String, Object>) item;
                    Map<String, Object> reply = McpJsonRpc.handle(msg, authorized, this::invokeTool);
                    if (reply != null) {
                        replies.add(reply);
                    }
                }
            }
            writeJson(out, 200, replies);
            return;
        }
        Map<String, Object> msg = Json.asObject(parsed);
        Map<String, Object> reply = McpJsonRpc.handle(msg, authorized, this::invokeTool);
        if (reply == null) {
            write(out, 204, "");
            return;
        }
        writeJson(out, 200, reply);
    }

    private void mcpCallHttp(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        String name = Json.str(body, "name");
        Map<String, Object> args = McpJsonRpc.params(body.get("arguments"));
        Object payload = invokeTool(name, args);
        writeJson(out, 200, McpJsonRpc.toolResult(payload, McpJsonRpc.isError(payload)));
    }

    Object invokeTool(String name, Map<String, Object> args) {
        McpToolRoutes.Mapped mapped = McpToolRoutes.map(name, args);
        if (mapped == null) {
            Map<String, Object> err = Json.obj();
            err.put("error", "unknown_tool");
            err.put("name", name);
            return err;
        }
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("content-type", "application/json");
            Request inner = new Request(mapped.method, mapped.path, mapped.query, headers, mapped.body);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            if ("/health".equals(mapped.path)) {
                Map<String, Object> health = Json.obj();
                health.put("ok", true);
                health.put("name", "SquidSec Burp AI Bridge");
                health.put("version", BridgeVersion.VERSION);
                health.put("interceptEnabled", api.proxy().isInterceptEnabled());
                return health;
            }
            route(inner, buf);
            return parseCapturedJson(buf.toByteArray());
        } catch (Exception e) {
            Map<String, Object> err = Json.obj();
            err.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            return err;
        }
    }

    static Object parseCapturedJson(byte[] http) {
        String raw = new String(http, StandardCharsets.UTF_8);
        int idx = raw.indexOf("\r\n\r\n");
        String body = idx >= 0 ? raw.substring(idx + 4) : raw;
        if (body.isBlank()) {
            return Json.obj();
        }
        return Json.parse(body);
    }

    private void route(Request ex, OutputStream out) throws IOException {
        String path = ex.path;
        switch (path + " " + ex.method.toUpperCase(Locale.ROOT)) {
            case "/scope/check GET" -> scopeCheck(ex, out);
            case "/scope/include POST" -> scopeMutate(ex, out, true);
            case "/scope/exclude POST" -> scopeMutate(ex, out, false);
            case "/proxy/intercept GET" -> interceptGet(out);
            case "/proxy/intercept POST" -> interceptSet(ex, out);
            case "/proxy/history GET" -> proxyHistory(ex, out);
            case "/proxy/history/item GET" -> proxyHistoryItem(ex, out);
            case "/rewrite/rules GET" -> rewriteList(out);
            case "/rewrite/rules POST" -> rewriteAdd(ex, out);
            case "/rewrite/rules/clear POST" -> rewriteClear(out);
            case "/rewrite/rules/delete POST" -> rewriteDelete(ex, out);
            case "/repeater POST" -> sendRepeater(ex, out);
            case "/intruder POST" -> sendIntruder(ex, out);
            case "/http/send POST" -> httpSend(ex, out);
            case "/sitemap GET" -> siteMap(ex, out);
            case "/project GET" -> writeJson(out, 200, burpTools.projectInfo());
            case "/cookies GET" -> writeJson(out, 200, burpTools.cookies());
            case "/scanner/issues GET" -> writeJson(
                    out,
                    200,
                    burpTools.issues(ex.query.get("urlPrefix"), parseInt(ex.query.get("limit"), 100)));
            case "/scanner/crawl POST" -> writeJson(out, 200, burpTools.startCrawl(requireUrl(ex)));
            case "/scanner/audit POST" -> writeJson(out, 200, burpTools.startAudit(requireUrl(ex)));
            case "/scanner/report POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                writeJson(out, 200, burpTools.generateScanReport(Json.str(b, "path", ""), Json.str(b, "format", "html")));
            }
            case "/collaborator/payload POST" ->
                    writeJson(out, 200, burpTools.collaboratorPayload(Json.str(readJsonObject(ex), "customData")));
            case "/collaborator/poll GET" -> writeJson(out, 200, burpTools.collaboratorPoll());
            case "/organizer GET" -> writeJson(out, 200, burpTools.organizerList(parseInt(ex.query.get("limit"), 100)));
            case "/organizer POST" -> writeJson(out, 200, burpTools.organizerSend(MessageCodec.buildRequest(readJsonObject(ex))));
            case "/websocket/history GET" -> writeJson(
                    out,
                    200,
                    burpTools.websocketHistory(parseInt(ex.query.get("limit"), 50), ex.query.get("contains")));
            case "/websocket/send POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                writeJson(out, 200, burpTools.websocketSend(Json.str(b, "url"), Json.str(b, "text", "")));
            }
            case "/proxy/annotate POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                writeJson(
                        out,
                        200,
                        burpTools.annotateHistory(Json.integer(b, "index", -1), Json.str(b, "notes"), Json.str(b, "color")));
            }
            case "/comparer POST" -> writeJson(out, 200, burpTools.sendToComparer(Json.str(readJsonObject(ex), "data", "")));
            case "/decoder POST" -> writeJson(out, 200, burpTools.sendToDecoder(Json.str(readJsonObject(ex), "data", "")));
            case "/import/bcheck POST" -> writeJson(out, 200, burpTools.importBcheck(Json.str(readJsonObject(ex), "path", "")));
            case "/import/bambda POST" -> writeJson(out, 200, burpTools.importBambda(Json.str(readJsonObject(ex), "path", "")));
            case "/analyze/keywords POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                writeJson(out, 200, burpTools.analyzeKeywords(splitCsv(Json.str(b, "keywords", "")), splitBlock(Json.str(b, "responses", ""))));
            }
            case "/analyze/variations POST" ->
                    writeJson(out, 200, burpTools.analyzeVariations(splitBlock(Json.str(readJsonObject(ex), "responses", ""))));
            case "/search GET" -> writeJson(
                    out, 200, burpTools.search(ex.query.getOrDefault("contains", ""), parseInt(ex.query.get("limit"), 50)));
            case "/tools/curl POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                Map<String, Object> r = Json.obj();
                r.put("ok", true);
                r.put("curl", EngagementTools.toCurl(Json.str(b, "raw", Json.str(b, "request", "")), Json.str(b, "url"), Json.bool(b, "https", true)));
                writeJson(out, 200, r);
            }
            case "/tools/finding POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                Map<String, Object> r = Json.obj();
                r.put("ok", true);
                r.put(
                        "finding",
                        EngagementTools.findingDraft(
                                Json.str(b, "title"),
                                Json.str(b, "url"),
                                Json.str(b, "description"),
                                Json.str(b, "raw", Json.str(b, "request", "")),
                                Json.str(b, "response", ""),
                                Json.str(b, "recommendation")));
                writeJson(out, 200, r);
            }
            case "/tools/endpoints POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                String lines = Json.str(b, "lines", "");
                Map<String, Object> r = Json.obj();
                r.put("ok", true);
                r.put("endpoints", EngagementTools.endpointMap(java.util.Arrays.asList(lines.split("\\r?\\n"))));
                writeJson(out, 200, r);
            }
            case "/tools/csrf POST" -> {
                Map<String, Object> b = readJsonObject(ex);
                Map<String, String> fields = new LinkedHashMap<>();
                String fs = Json.str(b, "fields", "");
                if (fs != null) {
                    for (String part : fs.split("&")) {
                        int eq = part.indexOf('=');
                        if (eq > 0) {
                            fields.put(part.substring(0, eq), part.substring(eq + 1));
                        }
                    }
                }
                Map<String, Object> r = Json.obj();
                r.put("ok", true);
                r.put("html", EngagementTools.csrfPoc(Json.str(b, "url", ""), Json.str(b, "method", "POST"), fields));
                writeJson(out, 200, r);
            }
            case "/tools/decode POST" -> writeJson(out, 200, EngagementTools.decodeAll(Json.str(readJsonObject(ex), "input", "")));
            case "/scope/from-program POST" -> scopeFromProgram(ex, out);
            case "/tools/evidence POST" -> evidencePack(ex, out);
            default -> {
                Map<String, Object> err = Json.obj();
                err.put("error", "not_found");
                err.put("path", path);
                err.put("method", ex.method);
                writeJson(out, 404, err);
            }
        }
    }

    private String requireUrl(Request ex) {
        Map<String, Object> b = readJsonObject(ex);
        String url = Json.str(b, "url");
        if (url == null || url.isBlank()) {
            url = ex.query.get("url");
        }
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("url is required");
        }
        return url;
    }

    private static List<String> splitCsv(String s) {
        List<String> out = new ArrayList<>();
        if (s == null || s.isBlank()) {
            return out;
        }
        for (String p : s.split(",")) {
            if (!p.isBlank()) {
                out.add(p.trim());
            }
        }
        return out;
    }

    private static List<String> splitBlock(String s) {
        List<String> out = new ArrayList<>();
        if (s == null || s.isBlank()) {
            return out;
        }
        for (String p : s.split("\\n---\\n")) {
            if (!p.isBlank()) {
                out.add(p.trim());
            }
        }
        return out;
    }

    private void scopeFromProgram(Request ex, OutputStream out) throws IOException {
        Map<String, Object> b = readJsonObject(ex);
        List<String> urls = EngagementTools.scopeUrlsFromProgramJson(Json.str(b, "json", ""));
        boolean apply = Json.bool(b, "apply", false);
        if (apply) {
            for (String u : urls) {
                api.scope().includeInScope(u);
            }
        }
        Map<String, Object> r = Json.obj();
        r.put("ok", true);
        r.put("urls", urls);
        r.put("applied", apply);
        writeJson(out, 200, r);
    }

    private void evidencePack(Request ex, OutputStream out) throws IOException {
        Map<String, Object> b = readJsonObject(ex);
        String path = Json.str(b, "path", "");
        String text = EngagementTools.findingDraft(
                Json.str(b, "title", "Evidence"),
                Json.str(b, "url", ""),
                Json.str(b, "description", "an evidence pack for this request/response pair."),
                Json.str(b, "raw", ""),
                Json.str(b, "response", ""),
                "Store this with the engagement report.");
        java.nio.file.Path p = java.nio.file.Path.of(path);
        java.nio.file.Files.createDirectories(p.getParent() == null ? java.nio.file.Path.of(".") : p.getParent());
        java.nio.file.Files.writeString(p, text, StandardCharsets.UTF_8);
        Map<String, Object> r = Json.obj();
        r.put("ok", true);
        r.put("path", path);
        writeJson(out, 200, r);
    }

    private boolean authorize(Request ex) {
        String token = config.token();
        if (token == null || token.isBlank()) {
            return true;
        }
        String auth = ex.header("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            if (token.equals(auth.substring(7).trim())) {
                return true;
            }
        }
        String key = ex.header("X-API-Key");
        return token.equals(key);
    }

    private void scopeCheck(Request ex, OutputStream out) throws IOException {
        Map<String, String> q = ex.query;
        String url = q.get("url");
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("query param url is required");
        }
        Map<String, Object> body = Json.obj();
        body.put("url", url);
        body.put("inScope", api.scope().isInScope(url));
        writeJson(out, 200, body);
    }

    private void scopeMutate(Request ex, OutputStream out, boolean include) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        String url = Json.str(body, "url");
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("url is required");
        }
        if (include) {
            api.scope().includeInScope(url);
        } else {
            api.scope().excludeFromScope(url);
        }
        Map<String, Object> result = Json.obj();
        result.put("ok", true);
        result.put("url", url);
        result.put("action", include ? "include" : "exclude");
        result.put("inScope", api.scope().isInScope(url));
        writeJson(out, 200, result);
    }

    private void interceptGet(OutputStream out) throws IOException {
        Map<String, Object> body = Json.obj();
        body.put("enabled", api.proxy().isInterceptEnabled());
        writeJson(out, 200, body);
    }

    private void interceptSet(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        boolean enabled = Json.bool(body, "enabled", false);
        if (enabled) {
            api.proxy().enableIntercept();
        } else {
            api.proxy().disableIntercept();
        }
        Map<String, Object> result = Json.obj();
        result.put("enabled", api.proxy().isInterceptEnabled());
        writeJson(out, 200, result);
    }

    private void proxyHistory(Request ex, OutputStream out) throws IOException {
        Map<String, String> q = ex.query;
        int offset = parseInt(q.get("offset"), 0);
        int limit = parseInt(q.get("limit"), 50);
        if (limit < 1) {
            limit = 1;
        }
        if (limit > 500) {
            limit = 500;
        }
        boolean includeBody = "true".equalsIgnoreCase(q.getOrDefault("includeBody", "false"));
        int bodyLimit = parseInt(q.get("bodyLimit"), 4000);
        String host = q.get("host");
        String method = q.get("method");
        String status = q.get("status");
        String contains = q.get("contains");
        String urlContains = q.get("urlContains");
        // Accept inScope and inScopeOnly (agents commonly send inScope=true)
        boolean inScopeOnly = truthy(q.get("inScopeOnly")) || truthy(q.get("inScope"));
        boolean caseSensitive = "true".equalsIgnoreCase(q.get("caseSensitive"));
        // format=http (default): Burp-style raw request/response strings
        // format=json: structured objects
        String format = q.getOrDefault("format", "http");
        if (!"json".equalsIgnoreCase(format)) {
            format = "http";
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<Object> items = Json.arr();
        int matched = 0;
        int total = history.size();

        for (int i = total - 1; i >= 0; i--) {
            ProxyHttpRequestResponse item = history.get(i);
            if (!matchesHistory(item, host, method, status, contains, urlContains, inScopeOnly, caseSensitive)) {
                continue;
            }
            if (matched < offset) {
                matched++;
                continue;
            }
            if (items.size() >= limit) {
                matched++;
                break;
            }
            boolean inScope = isItemInScope(item);
            items.add(MessageCodec.historyItemToJson(item, i, includeBody, bodyLimit, inScope, format));
            matched++;
        }

        Map<String, Object> result = Json.obj();
        result.put("totalHistory", total);
        result.put("matched", matched);
        result.put("offset", offset);
        result.put("limit", limit);
        result.put("returned", items.size());
        result.put("format", format);
        result.put("includeBody", includeBody);
        result.put("inScopeOnly", inScopeOnly);
        result.put("items", items);
        writeJson(out, 200, result);
    }

    private static boolean truthy(String v) {
        if (v == null) {
            return false;
        }
        return "true".equalsIgnoreCase(v) || "1".equals(v) || "yes".equalsIgnoreCase(v);
    }

    private boolean isItemInScope(ProxyHttpRequestResponse item) {
        try {
            String url = item.finalRequest().url();
            return url != null && !url.isBlank() && api.scope().isInScope(url);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean matchesHistory(
            ProxyHttpRequestResponse item,
            String host,
            String method,
            String status,
            String contains,
            String urlContains,
            boolean inScopeOnly,
            boolean caseSensitive) {
        try {
            HttpRequest req = item.finalRequest();
            if (host != null && !host.isBlank()) {
                String h = req.httpService() != null ? req.httpService().host() : "";
                if (h == null || !h.toLowerCase(Locale.ROOT).contains(host.toLowerCase(Locale.ROOT))) {
                    return false;
                }
            }
            if (method != null && !method.isBlank()) {
                if (!method.equalsIgnoreCase(req.method())) {
                    return false;
                }
            }
            if (status != null && !status.isBlank()) {
                HttpResponse resp = item.response();
                if (resp == null) {
                    return false;
                }
                if (!status.equals(String.valueOf(resp.statusCode()))) {
                    return false;
                }
            }
            String url = "";
            try {
                url = req.url();
            } catch (Exception ignored) {
            }
            if (urlContains != null && !urlContains.isBlank()) {
                if (url == null || !url.toLowerCase(Locale.ROOT).contains(urlContains.toLowerCase(Locale.ROOT))) {
                    return false;
                }
            }
            if (inScopeOnly) {
                if (url == null || url.isBlank() || !api.scope().isInScope(url)) {
                    return false;
                }
            }
            if (contains != null && !contains.isBlank()) {
                if (!item.contains(contains, caseSensitive)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void proxyHistoryItem(Request ex, OutputStream out) throws IOException {
        Map<String, String> q = ex.query;
        int index = parseInt(q.get("index"), -1);
        boolean includeBody = !"false".equalsIgnoreCase(q.getOrDefault("includeBody", "true"));
        int bodyLimit = parseInt(q.get("bodyLimit"), 100_000);
        String format = q.getOrDefault("format", "http");
        if (!"json".equalsIgnoreCase(format)) {
            format = "http";
        }

        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (index < 0 || index >= history.size()) {
            Map<String, Object> err = Json.obj();
            err.put("error", "not_found");
            err.put("hint", "Provide index (0-based position in proxy history list)");
            err.put("historySize", history.size());
            writeJson(out, 404, err);
            return;
        }
        ProxyHttpRequestResponse item = history.get(index);
        LogCtx ctx = logCtx.get();
        if (ctx != null) {
            try {
                ctx.setTargetView(item.finalRequest(), item.response(), Math.max(bodyLimit, 100_000));
            } catch (Exception ignored) {
            }
        }
        writeJson(
                out,
                200,
                MessageCodec.historyItemToJson(item, index, includeBody, bodyLimit, isItemInScope(item), format));
    }

    private void rewriteList(OutputStream out) throws IOException {
        List<Object> rules = Json.arr();
        for (RewriteEngine.Rule r : rewriteEngine.listRules()) {
            rules.add(r.toJson());
        }
        Map<String, Object> result = Json.obj();
        result.put("rules", rules);
        result.put("count", rules.size());
        writeJson(out, 200, result);
    }

    private void rewriteAdd(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        RewriteEngine.Rule rule = rewriteEngine.addRule(body);
        Map<String, Object> result = Json.obj();
        result.put("ok", true);
        result.put("rule", rule.toJson());
        writeJson(out, 200, result);
    }

    private void rewriteClear(OutputStream out) throws IOException {
        rewriteEngine.clearRules();
        Map<String, Object> result = Json.obj();
        result.put("ok", true);
        result.put("count", 0);
        writeJson(out, 200, result);
    }

    private void rewriteDelete(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        String id = Json.str(body, "id");
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id is required");
        }
        boolean removed = rewriteEngine.removeRule(id);
        Map<String, Object> result = Json.obj();
        result.put("ok", removed);
        result.put("id", id);
        writeJson(out, 200, result);
    }

    private void sendRepeater(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        HttpRequest req = MessageCodec.buildRequest(body);
        String name = Json.str(body, "tabName");
        if (name == null) {
            name = Json.str(body, "name");
        }
        if (name != null && !name.isBlank()) {
            api.repeater().sendToRepeater(req, name);
        } else {
            api.repeater().sendToRepeater(req);
        }
        LogCtx ctx = logCtx.get();
        if (ctx != null) {
            ctx.setTargetView(req, null, 200_000);
            ctx.viewResponseRaw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSent to Repeater"
                    + (name != null && !name.isBlank() ? " tab: " + name : "");
            ctx.viewStatus = 200;
        }
        Map<String, Object> result = Json.obj();
        result.put("ok", true);
        result.put("tool", "repeater");
        result.put("tabName", name);
        writeJson(out, 200, result);
    }

    private void sendIntruder(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        HttpRequest req = MessageCodec.buildRequest(body);
        String name = Json.str(body, "tabName");
        if (name == null) {
            name = Json.str(body, "name");
        }
        if (name != null && !name.isBlank()) {
            api.intruder().sendToIntruder(req, name);
        } else {
            api.intruder().sendToIntruder(req);
        }
        LogCtx ctx = logCtx.get();
        if (ctx != null) {
            ctx.setTargetView(req, null, 200_000);
            ctx.viewResponseRaw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSent to Intruder"
                    + (name != null && !name.isBlank() ? " tab: " + name : "");
            ctx.viewStatus = 200;
        }
        Map<String, Object> result = Json.obj();
        result.put("ok", true);
        result.put("tool", "intruder");
        result.put("tabName", name);
        writeJson(out, 200, result);
    }

    private void httpSend(Request ex, OutputStream out) throws IOException {
        Map<String, Object> body = readJsonObject(ex);
        HttpRequest req = MessageCodec.buildRequest(body);
        HttpResponse resp;
        String httpMode = Json.str(body, "httpMode");
        if (httpMode != null && !httpMode.isBlank()) {
            resp = burpTools.sendWithOptions(req, httpMode).response();
        } else {
            resp = sendForProxyHistory(req);
        }
        // History tab: show target request/response, not the bridge API envelope
        LogCtx ctx = logCtx.get();
        if (ctx != null) {
            ctx.setTargetView(req, resp, 500_000);
        }
        Map<String, Object> result = Json.obj();
        result.put("ok", true);
        // API payload still structured for agents; format=http-style raws included
        result.put("request", MessageCodec.requestRaw(req, true, 100_000));
        result.put("response", MessageCodec.responseRaw(resp, true, 100_000));
        if (resp != null) {
            result.put("status", (int) resp.statusCode());
        }
        try {
            result.put("url", req.url());
        } catch (Exception ignored) {
        }
        writeJson(out, 200, result);
    }

    private HttpResponse sendForProxyHistory(HttpRequest req) {
        HttpResponse resp = null;
        if (config.sendViaProxy()) {
            try {
                HttpRequest viaProxy =
                        AbsoluteProxyRequest.wrap(req, config.burpProxyHost(), config.burpProxyPort());
                resp = api.http().sendRequest(viaProxy).response();
            } catch (Exception e) {
                api.logging()
                        .logToError(
                                "AI Bridge send-via-proxy failed, falling back to direct send: "
                                        + e.getMessage());
            }
        }
        if (resp == null) {
            resp = api.http().sendRequest(req).response();
        }
        try {
            api.siteMap().add(HttpRequestResponse.httpRequestResponse(req, resp));
        } catch (Exception e) {
            api.logging().logToError("AI Bridge sitemap add failed: " + e.getMessage());
        }
        return resp;
    }

    private void siteMap(Request ex, OutputStream out) throws IOException {
        Map<String, String> q = ex.query;
        String prefix = q.getOrDefault("urlPrefix", "");
        int limit = parseInt(q.get("limit"), 200);
        if (limit > 1000) {
            limit = 1000;
        }

        List<Object> items = Json.arr();
        var source = (prefix == null || prefix.isBlank())
                ? api.siteMap().requestResponses()
                : api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix));
        source.stream()
                .limit(limit)
                .forEach(rr -> {
                    Map<String, Object> m = Json.obj();
                    try {
                        m.put("url", rr.request().url());
                        m.put("method", rr.request().method());
                        if (rr.response() != null) {
                            m.put("status", rr.response().statusCode());
                        }
                    } catch (Exception e) {
                        m.put("error", e.getMessage());
                    }
                    items.add(m);
                });
        Map<String, Object> result = Json.obj();
        result.put("urlPrefix", prefix);
        result.put("returned", items.size());
        result.put("items", items);
        writeJson(out, 200, result);
    }

    private Map<String, Object> apiDocs() {
        Map<String, Object> docs = Json.obj();
        docs.put("name", "SquidSec Burp AI Bridge");
        docs.put("version", BridgeVersion.VERSION);
        docs.put("bind", config.bindHost() + ":" + boundPort());
        docs.put(
                "auth",
                "Authorization: Bearer <token> or X-API-Key: <token> (token printed in Burp Extender output)");
        List<Object> endpoints = Json.arr();
        endpoints.add(endpoint("GET", "/health", "Health check (no auth)"));
        endpoints.add(endpoint("GET", "/scope/check?url=", "Is URL in suite scope"));
        endpoints.add(endpoint("POST", "/scope/include", "{url}"));
        endpoints.add(endpoint("POST", "/scope/exclude", "{url}"));
        endpoints.add(endpoint("GET", "/proxy/intercept", "Intercept enabled?"));
        endpoints.add(endpoint("POST", "/proxy/intercept", "{enabled:bool}"));
        endpoints.add(endpoint(
                "GET",
                "/proxy/history",
                "Query: offset,limit,host,method,status,contains,urlContains,inScope|inScopeOnly,"
                        + "includeBody,bodyLimit,format=http|json (default http = Burp-style raw request/response)"));
        endpoints.add(endpoint(
                "GET",
                "/proxy/history/item?index=",
                "Full history item; format=http|json, includeBody, bodyLimit"));
        endpoints.add(endpoint("GET", "/rewrite/rules", "List match/replace rules"));
        endpoints.add(endpoint(
                "POST",
                "/rewrite/rules",
                "{match,replace,phase:REQUEST|RESPONSE|BOTH,regex,urlContains,name,enabled}"));
        endpoints.add(endpoint("POST", "/rewrite/rules/delete", "{id}"));
        endpoints.add(endpoint("POST", "/rewrite/rules/clear", "{}"));
        endpoints.add(endpoint("POST", "/repeater", "{raw|request, host?, port?, https?, tabName?}"));
        endpoints.add(endpoint("POST", "/intruder", "{raw|request, host?, port?, https?, tabName?}"));
        endpoints.add(endpoint("POST", "/http/send", "Send request via Burp HTTP engine"));
        endpoints.add(endpoint("GET", "/sitemap?urlPrefix=&limit=", "Site map URLs"));
        endpoints.add(endpoint("GET", "/mcp/tools", "MCP tool discovery (no auth)"));
        endpoints.add(endpoint("POST", "/mcp", "MCP JSON-RPC: initialize, tools/list, tools/call, ping"));
        endpoints.add(endpoint("POST", "/mcp/call", "{name, arguments} invoke a discovered tool (auth)"));
        docs.put("endpoints", endpoints);
        return docs;
    }

    private static Map<String, Object> endpoint(String method, String path, String desc) {
        Map<String, Object> m = Json.obj();
        m.put("method", method);
        m.put("path", path);
        m.put("description", desc);
        return m;
    }

    private Map<String, Object> readJsonObject(Request ex) {
        String raw = ex.body == null ? "" : new String(ex.body, StandardCharsets.UTF_8);
        if (raw.isBlank()) {
            return Json.obj();
        }
        return Json.asObject(Json.parse(raw));
    }

    private static int parseInt(String s, int def) {
        if (s == null || s.isBlank()) {
            return def;
        }
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private void writeJson(OutputStream out, int status, Object body) throws IOException {
        write(out, status, Json.stringify(body));
    }

    private void write(OutputStream out, int status, String body) throws IOException {
        if (body == null) {
            body = "";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        String reason =
                switch (status) {
                    case 200 -> "OK";
                    case 204 -> "No Content";
                    case 401 -> "Unauthorized";
                    case 404 -> "Not Found";
                    case 500 -> "Internal Server Error";
                    default -> "OK";
                };
        String contentType = "application/json; charset=utf-8";
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(status).append(' ').append(reason).append("\r\n");
        sb.append("Content-Type: ").append(contentType).append("\r\n");
        sb.append("Content-Length: ").append(bytes.length).append("\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        String headerBlock = sb.toString();
        out.write(headerBlock.getBytes(StandardCharsets.US_ASCII));
        if (bytes.length > 0) {
            out.write(bytes);
        }
        out.flush();
        logExchange(status, contentType, body, headerBlock + body);
    }

    private void logExchange(int status, String contentType, String responseBody, String responseRaw) {
        if (historyLog == null) {
            return;
        }
        LogCtx ctx = logCtx.get();
        // Proxy-history style: only record actual target HTTP exchanges (e.g. /http/send).
        // Control-plane calls (/scope/check, /sitemap, /proxy/history, …) are not listed.
        if (ctx == null || !ctx.hasTarget || ctx.viewRequestRaw == null || ctx.viewRequestRaw.isBlank()) {
            return;
        }
        try {
            long duration = Math.max(0, System.currentTimeMillis() - ctx.startedMs);
            long id = historyLog.nextId();
            int logStatus = ctx.viewStatus != null ? ctx.viewStatus : status;
            String path = ctx.viewPath == null || ctx.viewPath.isBlank() ? "/" : ctx.viewPath;
            String query = ctx.viewQuery == null ? "" : ctx.viewQuery;
            String method = ctx.viewMethod == null ? "" : ctx.viewMethod;
            String host = ctx.viewHost == null ? "" : ctx.viewHost;
            String url = ctx.viewUrl;
            if (url == null || url.isBlank()) {
                StringBuilder u = new StringBuilder();
                u.append(ctx.viewHttps ? "https://" : "http://");
                u.append(host);
                if (ctx.viewPort > 0
                        && !((ctx.viewHttps && ctx.viewPort == 443) || (!ctx.viewHttps && ctx.viewPort == 80))) {
                    u.append(':').append(ctx.viewPort);
                }
                u.append(path);
                if (!query.isBlank()) {
                    u.append('?').append(query);
                }
                url = u.toString();
            }
            BridgeLogEntry entry = new BridgeLogEntry(
                    id,
                    Instant.now(),
                    ctx.client,
                    method,
                    path,
                    query,
                    url,
                    host,
                    ctx.viewPort,
                    ctx.viewHttps,
                    logStatus,
                    duration,
                    ctx.viewRequestRaw,
                    ctx.viewResponseRaw == null ? "" : ctx.viewResponseRaw);
            historyLog.add(entry);
        } catch (Exception e) {
            api.logging().logToError("AI Bridge history log failed: " + e.getMessage());
        }
    }

    private static String formatQuery(Map<String, String> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : query.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(e.getKey());
            if (e.getValue() != null && !e.getValue().isEmpty()) {
                sb.append('=').append(e.getValue());
            }
        }
        return sb.toString();
    }

    private String buildRequestRaw(Request req, String query, String body) {
        String target = req.path == null || req.path.isBlank() ? "/" : req.path;
        if (query != null && !query.isBlank()) {
            target = target + "?" + query;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(req.method == null ? "GET" : req.method)
                .append(' ')
                .append(target)
                .append(" HTTP/1.1\r\n");
        boolean hasHost = false;
        if (req.headers != null) {
            for (Map.Entry<String, String> h : req.headers.entrySet()) {
                String name = h.getKey();
                String value = h.getValue() == null ? "" : h.getValue();
                if ("host".equalsIgnoreCase(name)) {
                    hasHost = true;
                }
                // restore canonical-ish header names
                sb.append(capitalizeHeader(name)).append(": ").append(value).append("\r\n");
            }
        }
        if (!hasHost) {
            sb.append("Host: ")
                    .append(config.bindHost())
                    .append(':')
                    .append(boundPort())
                    .append("\r\n");
        }
        if (body != null && !body.isEmpty() && (req.headers == null || !req.headers.containsKey("content-length"))) {
            sb.append("Content-Length: ")
                    .append(body.getBytes(StandardCharsets.UTF_8).length)
                    .append("\r\n");
        }
        sb.append("\r\n");
        if (body != null) {
            sb.append(body);
        }
        return sb.toString();
    }

    private static String capitalizeHeader(String name) {
        if (name == null || name.isBlank()) {
            return "X-Header";
        }
        String[] parts = name.split("-");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                sb.append('-');
            }
            String p = parts[i];
            if (p.isEmpty()) {
                continue;
            }
            sb.append(Character.toUpperCase(p.charAt(0)));
            if (p.length() > 1) {
                sb.append(p.substring(1));
            }
        }
        return sb.toString();
    }

    /** Minimal HTTP/1.1 request parse (no external deps). */
    static final class Request {
        final String method;
        final String path;
        final Map<String, String> query;
        final Map<String, String> headers;
        final byte[] body;

        Request(String method, String path, Map<String, String> query, Map<String, String> headers, byte[] body) {
            this.method = method;
            this.path = path;
            this.query = query;
            this.headers = headers;
            this.body = body;
        }

        Request withPath(String newPath) {
            return new Request(method, newPath, query, headers, body);
        }

        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }

        static Request read(InputStream rawIn) throws IOException {
            BufferedInputStream in = new BufferedInputStream(rawIn);
            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isBlank()) {
                return null;
            }
            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 2) {
                return null;
            }
            String method = parts[0];
            String target = parts[1];

            Map<String, String> headers = new LinkedHashMap<>();
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    String value = line.substring(colon + 1).trim();
                    headers.put(name, value);
                }
            }

            int contentLength = 0;
            String cl = headers.get("content-length");
            if (cl != null) {
                try {
                    contentLength = Integer.parseInt(cl.trim());
                } catch (NumberFormatException ignored) {
                }
            }
            byte[] body = new byte[0];
            if (contentLength > 0) {
                body = in.readNBytes(contentLength);
            }

            String path;
            Map<String, String> query = new LinkedHashMap<>();
            try {
                // relative URI forms are fine for path+query
                URI uri = URI.create(target.contains("://") ? target : "http://localhost" + target);
                path = uri.getPath();
                if (path == null || path.isBlank()) {
                    path = "/";
                }
                String rawQuery = uri.getRawQuery();
                if (rawQuery != null && !rawQuery.isBlank()) {
                    for (String part : rawQuery.split("&")) {
                        int eq = part.indexOf('=');
                        if (eq < 0) {
                            query.put(urlDecode(part), "");
                        } else {
                            query.put(urlDecode(part.substring(0, eq)), urlDecode(part.substring(eq + 1)));
                        }
                    }
                }
            } catch (Exception e) {
                path = target;
            }

            return new Request(method, path, query, headers, body);
        }

        private static String readLine(InputStream in) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int prev = -1;
            while (true) {
                int b = in.read();
                if (b < 0) {
                    if (buf.size() == 0) {
                        return null;
                    }
                    break;
                }
                if (b == '\n') {
                    break;
                }
                if (b != '\r') {
                    buf.write(b);
                }
                prev = b;
                if (buf.size() > 16_384) {
                    throw new IOException("Header line too long");
                }
            }
            // silence unused
            if (prev == -2) {
                return null;
            }
            return buf.toString(StandardCharsets.US_ASCII);
        }

        private static String urlDecode(String s) {
            return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
        }
    }
}
