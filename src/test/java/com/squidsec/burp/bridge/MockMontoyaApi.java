package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

import java.io.PrintStream;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Standalone mock of Burp Montoya surfaces used by the AI Bridge.
 * Installs a minimal {@link MontoyaObjectFactory} so HttpRequest/HttpResponse static factories work.
 */
public final class MockMontoyaApi {

    public final MontoyaApi api;
    public final List<ProxyHttpRequestResponse> history = new CopyOnWriteArrayList<>();
    public final List<HttpRequestResponse> siteMap = new CopyOnWriteArrayList<>();
    public final List<String> scopeIncludes = new CopyOnWriteArrayList<>();
    public final List<String> scopeExcludes = new CopyOnWriteArrayList<>();
    public final List<String> repeaterTabs = new CopyOnWriteArrayList<>();
    public final List<String> intruderTabs = new CopyOnWriteArrayList<>();
    public final AtomicBoolean interceptEnabled = new AtomicBoolean(false);
    public final Map<String, String> stringPrefs = new ConcurrentHashMap<>();
    public final Map<String, Integer> intPrefs = new ConcurrentHashMap<>();
    public final Map<String, String> extStrings = new ConcurrentHashMap<>();
    public final Map<String, Integer> extInts = new ConcurrentHashMap<>();

    private MockMontoyaApi(MontoyaApi api) {
        this.api = api;
    }

    public static MockMontoyaApi create() {
        installObjectFactory();

        MockMontoyaApi state = new MockMontoyaApi(mock(MontoyaApi.class));
        state.wire();
        state.seedSampleData();
        return state;
    }

    private void wire() {
        Logging logging = mock(Logging.class);
        doAnswer(inv -> {
            System.out.println("[Burp-Out] " + inv.getArgument(0));
            return null;
        }).when(logging).logToOutput(anyString());
        doAnswer(inv -> {
            System.err.println("[Burp-Err] " + inv.getArgument(0));
            return null;
        }).when(logging).logToError(anyString());
        doAnswer(inv -> {
            System.err.println("[Burp-Err] " + inv.getArgument(0));
            Throwable t = inv.getArgument(1);
            if (t != null) {
                t.printStackTrace(System.err);
            }
            return null;
        }).when(logging).logToError(anyString(), any());
        when(logging.output()).thenReturn(System.out);
        when(logging.error()).thenReturn(System.err);
        when(api.logging()).thenReturn(logging);

        Extension extension = mock(Extension.class);
        when(api.extension()).thenReturn(extension);
        when(extension.registerUnloadingHandler(any())).thenReturn(mock(Registration.class));

        Preferences preferences = mock(Preferences.class);
        when(preferences.getString(anyString())).thenAnswer(inv -> stringPrefs.get(inv.getArgument(0)));
        doAnswer(inv -> {
            stringPrefs.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(preferences).setString(anyString(), anyString());
        when(preferences.getInteger(anyString())).thenAnswer(inv -> intPrefs.get(inv.getArgument(0)));
        doAnswer(inv -> {
            intPrefs.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(preferences).setInteger(anyString(), anyInt());
        when(preferences.stringKeys()).thenAnswer(inv -> Set.copyOf(stringPrefs.keySet()));
        when(preferences.integerKeys()).thenAnswer(inv -> Set.copyOf(intPrefs.keySet()));

        PersistedObject ext = mock(PersistedObject.class);
        when(ext.getString(anyString())).thenAnswer(inv -> extStrings.get(inv.getArgument(0)));
        doAnswer(inv -> {
            extStrings.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(ext).setString(anyString(), anyString());
        when(ext.getInteger(anyString())).thenAnswer(inv -> extInts.get(inv.getArgument(0)));
        doAnswer(inv -> {
            extInts.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(ext).setInteger(anyString(), anyInt());

        Persistence persistence = mock(Persistence.class);
        when(persistence.preferences()).thenReturn(preferences);
        when(persistence.extensionData()).thenReturn(ext);
        when(api.persistence()).thenReturn(persistence);

        Scope scope = mock(Scope.class);
        when(scope.isInScope(anyString())).thenAnswer(inv -> {
            String url = inv.getArgument(0);
            for (String ex : scopeExcludes) {
                if (url != null && url.startsWith(ex)) {
                    return false;
                }
            }
            if (scopeIncludes.isEmpty()) {
                return true;
            }
            for (String inc : scopeIncludes) {
                if (url != null && url.startsWith(inc)) {
                    return true;
                }
            }
            return false;
        });
        doAnswer(inv -> {
            String url = inv.getArgument(0);
            scopeIncludes.add(url);
            scopeExcludes.removeIf(u -> u.equals(url));
            return null;
        }).when(scope).includeInScope(anyString());
        doAnswer(inv -> {
            String url = inv.getArgument(0);
            scopeExcludes.add(url);
            return null;
        }).when(scope).excludeFromScope(anyString());
        when(api.scope()).thenReturn(scope);

        Proxy proxy = mock(Proxy.class);
        when(proxy.isInterceptEnabled()).thenAnswer(inv -> interceptEnabled.get());
        doAnswer(inv -> {
            interceptEnabled.set(true);
            return null;
        }).when(proxy).enableIntercept();
        doAnswer(inv -> {
            interceptEnabled.set(false);
            return null;
        }).when(proxy).disableIntercept();
        when(proxy.history()).thenAnswer(inv -> List.copyOf(history));
        when(proxy.registerRequestHandler(any(ProxyRequestHandler.class))).thenReturn(mock(Registration.class));
        when(proxy.registerResponseHandler(any(ProxyResponseHandler.class))).thenReturn(mock(Registration.class));
        when(api.proxy()).thenReturn(proxy);

        Repeater repeater = mock(Repeater.class);
        doAnswer(inv -> {
            HttpRequest req = inv.getArgument(0);
            String tab = inv.getArguments().length > 1 ? inv.getArgument(1) : "(default)";
            repeaterTabs.add(tab + " :: " + safeUrl(req));
            System.out.println("[Mock] sendToRepeater tab=" + tab + " url=" + safeUrl(req));
            return null;
        }).when(repeater).sendToRepeater(any(HttpRequest.class));
        doAnswer(inv -> {
            HttpRequest req = inv.getArgument(0);
            String tab = inv.getArgument(1);
            repeaterTabs.add(tab + " :: " + safeUrl(req));
            System.out.println("[Mock] sendToRepeater tab=" + tab + " url=" + safeUrl(req));
            return null;
        }).when(repeater).sendToRepeater(any(HttpRequest.class), anyString());
        when(api.repeater()).thenReturn(repeater);

        Intruder intruder = mock(Intruder.class);
        doAnswer(inv -> {
            HttpRequest req = inv.getArgument(0);
            String tab = inv.getArguments().length > 1 ? inv.getArgument(1) : "(default)";
            intruderTabs.add(tab + " :: " + safeUrl(req));
            System.out.println("[Mock] sendToIntruder tab=" + tab + " url=" + safeUrl(req));
            return null;
        }).when(intruder).sendToIntruder(any(HttpRequest.class));
        doAnswer(inv -> {
            HttpRequest req = inv.getArgument(0);
            String tab = inv.getArgument(1);
            intruderTabs.add(tab + " :: " + safeUrl(req));
            System.out.println("[Mock] sendToIntruder tab=" + tab + " url=" + safeUrl(req));
            return null;
        }).when(intruder).sendToIntruder(any(HttpRequest.class), anyString());
        when(api.intruder()).thenReturn(intruder);

        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(inv -> {
            HttpRequest req = inv.getArgument(0);
            HttpResponse resp = fakeResponse(200, "OK", "text/plain", "mock response for " + safeUrl(req));
            return fakeRequestResponse(req, resp);
        });
        when(api.http()).thenReturn(http);

        SiteMap map = mock(SiteMap.class);
        when(map.requestResponses()).thenAnswer(inv -> List.copyOf(siteMap));
        doAnswer(inv -> {
            HttpRequestResponse rr = inv.getArgument(0);
            siteMap.add(rr);
            return null;
        }).when(map).add(any(HttpRequestResponse.class));
        when(api.siteMap()).thenReturn(map);
    }

    private void seedSampleData() {
        scopeIncludes.add("https://example.com");

        HttpRequest r1 = fakeRequest("GET", "https://example.com/", "example.com", 443, true, "");
        HttpResponse s1 = fakeResponse(200, "OK", "text/html", "<html>hello example</html>");
        history.add(fakeHistoryItem(r1, s1, false));

        HttpRequest r2 = fakeRequest(
                "POST",
                "https://api.example.com/v1/login",
                "api.example.com",
                443,
                true,
                "user=admin&pass=test");
        HttpResponse s2 = fakeResponse(401, "Unauthorized", "application/json", "{\"error\":\"invalid\"}");
        history.add(fakeHistoryItem(r2, s2, true));

        HttpRequest r3 = fakeRequest("GET", "https://out-of-scope.test/path", "out-of-scope.test", 443, true, "");
        HttpResponse s3 = fakeResponse(302, "Found", "text/plain", "redirect");
        history.add(fakeHistoryItem(r3, s3, false));

        siteMap.add(fakeRequestResponse(r1, s1));
        siteMap.add(fakeRequestResponse(r2, s2));
    }

    public void addHistory(HttpRequest req, HttpResponse resp) {
        history.add(fakeHistoryItem(req, resp, false));
    }

    static void installObjectFactory() {
        MontoyaObjectFactory factory = mock(MontoyaObjectFactory.class, inv -> {
            String name = inv.getMethod().getName();
            Object[] args = inv.getArguments();
            switch (name) {
                case "httpService" -> {
                    if (args.length == 1) {
                        return fakeService(String.valueOf(args[0]), 443, true);
                    }
                    if (args.length == 2) {
                        return fakeService(String.valueOf(args[0]), (Boolean) args[1] ? 443 : 80, (Boolean) args[1]);
                    }
                    return fakeService(String.valueOf(args[0]), (Integer) args[1], (Boolean) args[2]);
                }
                case "httpHeader" -> {
                    if (args.length == 2 && args[0] instanceof String) {
                        return fakeHeader((String) args[0], (String) args[1]);
                    }
                    if (args.length == 1 && args[0] instanceof String) {
                        String raw = (String) args[0];
                        int colon = raw.indexOf(':');
                        if (colon > 0) {
                            return fakeHeader(raw.substring(0, colon).trim(), raw.substring(colon + 1).trim());
                        }
                        return fakeHeader(raw, "");
                    }
                    return fakeHeader("X-Mock", "");
                }
                case "httpRequest" -> {
                    if (args.length == 0) {
                        return fakeRequest("GET", "https://localhost/", "localhost", 443, true, "");
                    }
                    if (args.length == 1 && args[0] instanceof String) {
                        return parseRawRequest(null, (String) args[0]);
                    }
                    if (args.length == 1 && args[0] instanceof ByteArray) {
                        return parseRawRequest(null, ((ByteArray) args[0]).toString());
                    }
                    if (args.length == 2 && args[0] instanceof HttpService) {
                        HttpService svc = (HttpService) args[0];
                        String raw = args[1] instanceof ByteArray ba ? ba.toString() : String.valueOf(args[1]);
                        return parseRawRequest(svc, raw);
                    }
                    return fakeRequest("GET", "https://localhost/", "localhost", 443, true, "");
                }
                case "httpRequestFromUrl" -> {
                    String url = String.valueOf(args[0]);
                    return fakeRequestFromUrl(url);
                }
                case "httpResponse" -> {
                    if (args.length == 0) {
                        return fakeResponse(200, "OK", "text/plain", "");
                    }
                    String raw = args[0] instanceof ByteArray ba ? ba.toString() : String.valueOf(args[0]);
                    return parseRawResponse(raw);
                }
                case "httpRequestResponse" -> {
                    HttpRequest req = (HttpRequest) args[0];
                    HttpResponse resp = args.length > 1 ? (HttpResponse) args[1] : null;
                    return fakeRequestResponse(req, resp);
                }
                case "annotations" -> {
                    return fakeAnnotations(args.length > 0 && args[0] instanceof String ? (String) args[0] : "");
                }
                case "byteArray" -> {
                    if (args[0] instanceof byte[] b) {
                        return fakeByteArray(b);
                    }
                    if (args[0] instanceof String s) {
                        return fakeByteArray(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    }
                    return fakeByteArray(new byte[0]);
                }
                case "byteArrayOfLength" -> {
                    return fakeByteArray(new byte[(Integer) args[0]]);
                }
                default -> {
                    // Return a mock of the declared return type when possible
                    Class<?> rt = inv.getMethod().getReturnType();
                    if (rt == void.class || rt == Void.class) {
                        return null;
                    }
                    if (rt.isPrimitive()) {
                        if (rt == boolean.class) {
                            return false;
                        }
                        if (rt == int.class || rt == short.class || rt == byte.class || rt == long.class) {
                            return 0;
                        }
                        if (rt == double.class || rt == float.class) {
                            return 0.0;
                        }
                        if (rt == char.class) {
                            return '\0';
                        }
                    }
                    if (rt == String.class) {
                        return "";
                    }
                    if (rt == List.class) {
                        return List.of();
                    }
                    try {
                        return mock(rt);
                    } catch (Exception e) {
                        return null;
                    }
                }
            }
        });
        ObjectFactoryLocator.FACTORY = factory;
    }

    static HttpService fakeService(String host, int port, boolean secure) {
        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn(host);
        when(svc.port()).thenReturn(port);
        when(svc.secure()).thenReturn(secure);
        when(svc.ipAddress()).thenReturn("127.0.0.1");
        when(svc.toString()).thenReturn(host + ":" + port);
        return svc;
    }

    static HttpHeader fakeHeader(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        when(h.toString()).thenReturn(name + ": " + value);
        return h;
    }

    static Annotations fakeAnnotations(String notes) {
        Annotations a = mock(Annotations.class);
        when(a.notes()).thenReturn(notes == null ? "" : notes);
        when(a.hasNotes()).thenReturn(notes != null && !notes.isBlank());
        when(a.hasHighlightColor()).thenReturn(false);
        when(a.highlightColor()).thenReturn(null);
        return a;
    }

    static ByteArray fakeByteArray(byte[] data) {
        ByteArray ba = mock(ByteArray.class);
        when(ba.getBytes()).thenReturn(data);
        when(ba.length()).thenReturn(data.length);
        when(ba.toString()).thenReturn(new String(data, java.nio.charset.StandardCharsets.UTF_8));
        return ba;
    }

    static HttpRequest fakeRequest(
            String method, String url, String host, int port, boolean secure, String body) {
        HttpService svc = fakeService(host, port, secure);
        String path = "/";
        try {
            java.net.URI uri = java.net.URI.create(url);
            path = uri.getRawPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (uri.getRawQuery() != null) {
                path = path + "?" + uri.getRawQuery();
            }
        } catch (Exception ignored) {
        }
        String raw = method + " " + path + " HTTP/1.1\r\n"
                + "Host: " + host + (port == 80 || port == 443 ? "" : ":" + port) + "\r\n"
                + "User-Agent: MockBurp/1.0\r\n"
                + "\r\n"
                + (body == null ? "" : body);
        return buildRequestMock(svc, method, url, path, body, raw);
    }

    static HttpRequest fakeRequestFromUrl(String url) {
        try {
            java.net.URI uri = java.net.URI.create(url);
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            int port = uri.getPort() > 0 ? uri.getPort() : (secure ? 443 : 80);
            String host = uri.getHost() == null ? "localhost" : uri.getHost();
            return fakeRequest("GET", url, host, port, secure, "");
        } catch (Exception e) {
            return fakeRequest("GET", url, "localhost", 443, true, "");
        }
    }

    static HttpRequest parseRawRequest(HttpService svc, String raw) {
        String normalized = raw == null ? "" : raw.replace("\r\n", "\n").replace("\n", "\r\n");
        String method = "GET";
        String path = "/";
        String host = svc != null ? svc.host() : "localhost";
        int port = svc != null ? svc.port() : 443;
        boolean secure = svc == null || svc.secure();
        String body = "";

        String[] parts = normalized.split("\r\n\r\n", 2);
        String head = parts[0];
        if (parts.length > 1) {
            body = parts[1];
        }
        String[] lines = head.split("\r\n");
        if (lines.length > 0) {
            String[] rl = lines[0].split(" ", 3);
            if (rl.length >= 2) {
                method = rl[0];
                path = rl[1];
            }
        }
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String name = lines[i].substring(0, colon).trim();
                String value = lines[i].substring(colon + 1).trim();
                if (name.equalsIgnoreCase("Host")) {
                    if (value.contains(":")) {
                        String[] hp = value.split(":", 2);
                        host = hp[0];
                        try {
                            port = Integer.parseInt(hp[1]);
                        } catch (NumberFormatException ignored) {
                        }
                    } else {
                        host = value;
                    }
                }
            }
        }
        if (svc == null) {
            svc = fakeService(host, port, secure);
        }
        String scheme = secure ? "https" : "http";
        String url = scheme + "://" + host + (port == 80 || port == 443 ? "" : ":" + port) + path;
        return buildRequestMock(svc, method, url, path, body, normalized);
    }

    private static HttpRequest buildRequestMock(
            HttpService svc, String method, String url, String path, String body, String raw) {
        HttpRequest req = mock(HttpRequest.class);
        when(req.httpService()).thenReturn(svc);
        when(req.method()).thenReturn(method);
        when(req.url()).thenReturn(url);
        when(req.path()).thenReturn(path);
        when(req.httpVersion()).thenReturn("HTTP/1.1");
        when(req.bodyToString()).thenReturn(body == null ? "" : body);
        when(req.toString()).thenReturn(raw);
        when(req.headers()).thenAnswer(inv -> {
            List<HttpHeader> headers = new ArrayList<>();
            headers.add(fakeHeader("Host", svc.host()));
            headers.add(fakeHeader("User-Agent", "MockBurp/1.0"));
            return headers;
        });
        when(req.withService(any(HttpService.class))).thenAnswer(inv -> {
            HttpService ns = inv.getArgument(0);
            return buildRequestMock(ns, method, url, path, body, raw);
        });
        when(req.contains(anyString(), anyBoolean())).thenAnswer(inv -> {
            String needle = inv.getArgument(0);
            boolean cs = inv.getArgument(1);
            String hay = raw == null ? "" : raw;
            return cs ? hay.contains(needle) : hay.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
        });
        return req;
    }

    static HttpResponse fakeResponse(int status, String reason, String contentType, String body) {
        String raw = "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + (body == null ? 0 : body.length()) + "\r\n"
                + "\r\n"
                + (body == null ? "" : body);
        return parseRawResponse(raw);
    }

    static HttpResponse parseRawResponse(String raw) {
        String normalized = raw == null ? "" : raw.replace("\r\n", "\n").replace("\n", "\r\n");
        short status = 200;
        String reason = "OK";
        String body = "";
        String[] parts = normalized.split("\r\n\r\n", 2);
        String head = parts[0];
        if (parts.length > 1) {
            body = parts[1];
        }
        String[] lines = head.split("\r\n");
        if (lines.length > 0 && lines[0].toUpperCase(Locale.ROOT).startsWith("HTTP/")) {
            String[] rl = lines[0].split(" ", 3);
            if (rl.length >= 2) {
                try {
                    status = Short.parseShort(rl[1]);
                } catch (NumberFormatException ignored) {
                }
            }
            if (rl.length >= 3) {
                reason = rl[2];
            }
        }
        List<HttpHeader> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.add(fakeHeader(lines[i].substring(0, colon).trim(), lines[i].substring(colon + 1).trim()));
            }
        }
        HttpResponse resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(status);
        when(resp.reasonPhrase()).thenReturn(reason);
        when(resp.httpVersion()).thenReturn("HTTP/1.1");
        when(resp.bodyToString()).thenReturn(body);
        when(resp.toString()).thenReturn(normalized);
        when(resp.headers()).thenReturn(headers);
        String bodyFinal = body;
        when(resp.contains(anyString(), anyBoolean())).thenAnswer(inv -> {
            String needle = inv.getArgument(0);
            boolean cs = inv.getArgument(1);
            String hay = normalized;
            return cs ? hay.contains(needle) : hay.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
        });
        when(resp.contains(any(Pattern.class))).thenAnswer(inv -> {
            Pattern p = inv.getArgument(0);
            return p.matcher(normalized).find();
        });
        // silence unused
        if (bodyFinal == null) {
            return resp;
        }
        return resp;
    }

    static HttpRequestResponse fakeRequestResponse(HttpRequest req, HttpResponse resp) {
        Annotations notes = fakeAnnotations("");
        String url = safeUrl(req);
        HttpService svc = req == null ? null : req.httpService();
        short status = resp == null ? 0 : resp.statusCode();
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(req);
        when(rr.response()).thenReturn(resp);
        when(rr.hasResponse()).thenReturn(resp != null);
        when(rr.url()).thenReturn(url);
        when(rr.httpService()).thenReturn(svc);
        when(rr.annotations()).thenReturn(notes);
        if (resp != null) {
            when(rr.statusCode()).thenReturn(status);
        }
        return rr;
    }

    static ProxyHttpRequestResponse fakeHistoryItem(HttpRequest req, HttpResponse resp, boolean edited) {
        Annotations notes = fakeAnnotations(edited ? "edited sample" : "");
        HttpService svc = req == null ? null : req.httpService();
        String url = safeUrl(req);
        String method = req == null ? "" : req.method();
        String path = req == null ? "" : req.path();
        String host = svc == null ? "" : svc.host();
        int port = svc == null ? 0 : svc.port();
        boolean secure = svc != null && svc.secure();
        String hay = (req == null ? "" : req.toString()) + (resp == null ? "" : resp.toString());

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.request()).thenReturn(req);
        when(item.finalRequest()).thenReturn(req);
        when(item.response()).thenReturn(resp);
        when(item.originalResponse()).thenReturn(resp);
        when(item.hasResponse()).thenReturn(resp != null);
        when(item.edited()).thenReturn(edited);
        when(item.time()).thenReturn(ZonedDateTime.now());
        when(item.listenerPort()).thenReturn(8080);
        when(item.annotations()).thenReturn(notes);
        when(item.httpService()).thenReturn(svc);
        when(item.url()).thenReturn(url);
        when(item.method()).thenReturn(method);
        when(item.path()).thenReturn(path);
        when(item.host()).thenReturn(host);
        when(item.port()).thenReturn(port);
        when(item.secure()).thenReturn(secure);
        when(item.contains(anyString(), anyBoolean())).thenAnswer(inv -> {
            String needle = inv.getArgument(0);
            boolean cs = inv.getArgument(1);
            return cs ? hay.contains(needle) : hay.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
        });
        when(item.contains(any(Pattern.class))).thenAnswer(inv -> {
            Pattern p = inv.getArgument(0);
            return p.matcher(hay).find();
        });
        return item;
    }

    private static String safeUrl(HttpRequest req) {
        if (req == null) {
            return "";
        }
        try {
            return req.url();
        } catch (Exception e) {
            return "";
        }
    }
}
