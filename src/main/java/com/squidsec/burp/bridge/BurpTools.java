package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.project.Project;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.websocket.extension.ExtensionWebSocket;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** Live Burp tool surface. Pro-only calls fail soft on Community. */
public final class BurpTools {

    public static final String PREF_COLLAB_KEY = "squidsec.bridge.collaborator.secret";

    private final MontoyaApi api;
    private CollaboratorClient collaboratorClient;
    private final List<String> scanNotes = new CopyOnWriteArrayList<>();

    public BurpTools(MontoyaApi api) {
        this.api = api;
    }

    public Map<String, Object> projectInfo() {
        Map<String, Object> m = Json.obj();
        try {
            Project p = api.project();
            try {
                m.put("name", p.name());
            } catch (Exception e) {
                m.put("name", null);
            }
        } catch (Exception e) {
            m.put("projectError", e.getMessage());
        }
        try {
            m.put("burpVersion", String.valueOf(api.burpSuite().version()));
        } catch (Exception e) {
            m.put("burpVersion", null);
        }
        try {
            m.put("optionsJson", api.burpSuite().exportProjectOptionsAsJson());
        } catch (Exception e) {
            try {
                m.put("optionsJson", api.burpSuite().exportProjectOptionsAsJson("project_options"));
            } catch (Exception e2) {
                m.put("optionsJson", null);
            }
        }
        return m;
    }

    public Map<String, Object> cookies() {
        Map<String, Object> m = Json.obj();
        try {
            List<Object> items = Json.arr();
            for (Cookie c : api.http().cookieJar().cookies()) {
                Map<String, Object> row = Json.obj();
                row.put("name", c.name());
                row.put("value", c.value());
                row.put("domain", c.domain());
                row.put("path", c.path());
                items.add(row);
            }
            m.put("ok", true);
            m.put("cookies", items);
        } catch (Exception e) {
            return err(e);
        }
        return m;
    }

    public Map<String, Object> issues(String urlPrefix, int limit) {
        int cap = Math.min(Math.max(limit, 1), 500);
        try {
            List<AuditIssue> all = api.siteMap().issues();
            List<Object> items = Json.arr();
            for (AuditIssue issue : all) {
                if (items.size() >= cap) {
                    break;
                }
                String url = "";
                try {
                    url = issue.baseUrl();
                } catch (Exception ignored) {
                }
                if (urlPrefix != null && !urlPrefix.isBlank() && !url.toLowerCase(Locale.ROOT).startsWith(urlPrefix.toLowerCase(Locale.ROOT))) {
                    continue;
                }
                Map<String, Object> row = Json.obj();
                row.put("name", issue.name());
                row.put("severity", String.valueOf(issue.severity()));
                row.put("confidence", String.valueOf(issue.confidence()));
                row.put("url", url);
                try {
                    row.put("detail", issue.detail());
                } catch (Exception ignored) {
                }
                items.add(row);
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("returned", items.size());
            m.put("items", items);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> startCrawl(String seedUrl) {
        try {
            api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(seedUrl));
            scanNotes.add("crawl " + seedUrl);
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("started", "crawl");
            m.put("seedUrl", seedUrl);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> startAudit(String seedUrl) {
        try {
            AuditConfiguration cfg =
                    AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            api.scanner().startAudit(cfg);
            scanNotes.add("audit " + seedUrl);
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("started", "audit");
            m.put("seedUrl", seedUrl);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> generateScanReport(String path, String format) {
        try {
            ReportFormat fmt = "xml".equalsIgnoreCase(format) ? ReportFormat.XML : ReportFormat.HTML;
            api.scanner().generateReport(api.siteMap().issues(), fmt, Path.of(path));
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("path", path);
            m.put("format", fmt.name());
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> collaboratorPayload(String customData) {
        try {
            CollaboratorClient client = collaborator();
            CollaboratorPayload payload = customData == null || customData.isBlank()
                    ? client.generatePayload()
                    : client.generatePayload(customData);
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("payload", payload.toString());
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> collaboratorPoll() {
        try {
            List<Object> items = Json.arr();
            for (Interaction i : collaborator().getAllInteractions()) {
                Map<String, Object> row = Json.obj();
                row.put("id", String.valueOf(i.id()));
                row.put("type", String.valueOf(i.type()));
                row.put("time", String.valueOf(i.timeStamp()));
                items.add(row);
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("interactions", items);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> organizerList(int limit) {
        int cap = Math.min(Math.max(limit, 1), 500);
        try {
            List<Object> items = Json.arr();
            for (OrganizerItem item : api.organizer().items()) {
                if (items.size() >= cap) {
                    break;
                }
                Map<String, Object> row = Json.obj();
                try {
                    row.put("url", item.request().url());
                    row.put("method", item.request().method());
                } catch (Exception ignored) {
                }
                items.add(row);
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("items", items);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> organizerSend(HttpRequest req) {
        try {
            api.organizer().sendToOrganizer(req);
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> websocketHistory(int limit, String contains) {
        int cap = Math.min(Math.max(limit, 1), 200);
        try {
            List<ProxyWebSocketMessage> hist = api.proxy().webSocketHistory();
            List<Object> items = Json.arr();
            String needle = contains == null ? "" : contains.toLowerCase(Locale.ROOT);
            for (int i = hist.size() - 1; i >= 0 && items.size() < cap; i--) {
                ProxyWebSocketMessage msg = hist.get(i);
                String payload = "";
                try {
                    payload = msg.payload().toString();
                } catch (Exception ignored) {
                }
                if (!needle.isBlank() && !payload.toLowerCase(Locale.ROOT).contains(needle)) {
                    continue;
                }
                Map<String, Object> row = Json.obj();
                row.put("index", i);
                row.put("payload", payload.length() > 4000 ? payload.substring(0, 4000) : payload);
                try {
                    row.put("direction", String.valueOf(msg.direction()));
                } catch (Exception ignored) {
                }
                items.add(row);
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("returned", items.size());
            m.put("items", items);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> websocketSend(String upgradeUrl, String text) {
        try {
            HttpRequest upgrade = HttpRequest.httpRequestFromUrl(upgradeUrl);
            ExtensionWebSocketCreation created = api.websockets().createWebSocket(upgrade);
            ExtensionWebSocket ws = created.webSocket().orElseThrow(() -> new IllegalStateException("websocket not created"));
            ws.sendTextMessage(text == null ? "" : text);
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("status", String.valueOf(created.status()));
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> annotateHistory(int index, String notes, String color) {
        try {
            List<ProxyHttpRequestResponse> hist = api.proxy().history();
            if (index < 0 || index >= hist.size()) {
                return err("index out of range");
            }
            Annotations a = hist.get(index).annotations();
            if (notes != null) {
                a.setNotes(notes);
            }
            if (color != null && !color.isBlank()) {
                a.setHighlightColor(HighlightColor.valueOf(color.trim().toUpperCase(Locale.ROOT)));
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("index", index);
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> sendToComparer(String data) {
        try {
            api.comparer().sendToComparer(ByteArray.byteArray(data == null ? "" : data));
            return ok();
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> sendToDecoder(String data) {
        try {
            api.decoder().sendToDecoder(ByteArray.byteArray(data == null ? "" : data));
            return ok();
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> importBcheck(String path) {
        try {
            api.scanner().bChecks().importBCheck(path);
            return ok();
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> importBambda(String path) {
        try {
            api.bambda().importBambda(path);
            return ok();
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> analyzeKeywords(List<String> keywords, List<String> responses) {
        try {
            ResponseKeywordsAnalyzer az = api.http().createResponseKeywordsAnalyzer(keywords);
            if (responses != null) {
                for (String r : responses) {
                    az.updateWith(HttpResponse.httpResponse(r == null ? "HTTP/1.1 200 OK\r\n\r\n" : r));
                }
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("variantKeywords", String.valueOf(az.variantKeywords()));
            m.put("invariantKeywords", String.valueOf(az.invariantKeywords()));
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> analyzeVariations(List<String> responses) {
        try {
            ResponseVariationsAnalyzer az = api.http().createResponseVariationsAnalyzer();
            if (responses != null) {
                for (String r : responses) {
                    az.updateWith(HttpResponse.httpResponse(r == null ? "HTTP/1.1 200 OK\r\n\r\n" : r));
                }
            }
            Map<String, Object> m = Json.obj();
            m.put("ok", true);
            m.put("variantAttributes", String.valueOf(az.variantAttributes()));
            m.put("invariantAttributes", String.valueOf(az.invariantAttributes()));
            return m;
        } catch (Exception e) {
            return err(e);
        }
    }

    public HttpRequestResponse sendWithOptions(HttpRequest req, String httpMode) {
        if (httpMode != null && !httpMode.isBlank()) {
            try {
                HttpMode mode = HttpMode.valueOf(httpMode.trim().toUpperCase(Locale.ROOT).replace('-', '_'));
                return api.http().sendRequest(req, RequestOptions.requestOptions().withHttpMode(mode));
            } catch (Exception ignored) {
            }
            try {
                return api.http().sendRequest(req, HttpMode.valueOf(httpMode.trim().toUpperCase(Locale.ROOT)));
            } catch (Exception ignored) {
            }
        }
        return api.http().sendRequest(req);
    }

    public Map<String, Object> sitemapAdd(HttpRequest req, HttpResponse resp) {
        try {
            api.siteMap().add(HttpRequestResponse.httpRequestResponse(req, resp));
            return ok();
        } catch (Exception e) {
            return err(e);
        }
    }

    public Map<String, Object> search(String needle, int limit) {
        int cap = Math.min(Math.max(limit, 1), 100);
        String n = needle == null ? "" : needle.toLowerCase(Locale.ROOT);
        List<Object> hits = Json.arr();
        try {
            List<ProxyHttpRequestResponse> hist = api.proxy().history();
            for (int i = hist.size() - 1; i >= 0 && hits.size() < cap; i--) {
                ProxyHttpRequestResponse item = hist.get(i);
                String hay = "";
                try {
                    hay = item.request().toString() + (item.response() == null ? "" : item.response().toString());
                } catch (Exception ignored) {
                }
                if (hay.toLowerCase(Locale.ROOT).contains(n)) {
                    Map<String, Object> row = Json.obj();
                    row.put("source", "proxy");
                    row.put("index", i);
                    try {
                        row.put("url", item.request().url());
                    } catch (Exception ignored) {
                    }
                    hits.add(row);
                }
            }
        } catch (Exception ignored) {
        }
        Map<String, Object> m = Json.obj();
        m.put("ok", true);
        m.put("hits", hits);
        return m;
    }

    private CollaboratorClient collaborator() {
        if (collaboratorClient != null) {
            return collaboratorClient;
        }
        String stored = api.persistence().preferences().getString(PREF_COLLAB_KEY);
        if (stored != null && !stored.isBlank()) {
            try {
                collaboratorClient = api.collaborator().restoreClient(SecretKey.secretKey(stored));
                return collaboratorClient;
            } catch (Exception ignored) {
            }
        }
        collaboratorClient = api.collaborator().createClient();
        try {
            api.persistence().preferences().setString(PREF_COLLAB_KEY, collaboratorClient.getSecretKey().toString());
        } catch (Exception ignored) {
        }
        return collaboratorClient;
    }

    private static Map<String, Object> ok() {
        Map<String, Object> m = Json.obj();
        m.put("ok", true);
        return m;
    }

    private static Map<String, Object> err(Exception e) {
        return err(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
    }

    private static Map<String, Object> err(String msg) {
        Map<String, Object> m = Json.obj();
        m.put("ok", false);
        m.put("error", msg);
        return m;
    }
}
