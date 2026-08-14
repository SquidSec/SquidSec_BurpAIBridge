package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Match/replace rules applied to proxied traffic (request and/or response body text).
 */
public final class RewriteEngine implements ProxyRequestHandler, ProxyResponseHandler {

    public enum Phase {
        REQUEST,
        RESPONSE,
        BOTH
    }

    public static final class Rule {
        public final String id;
        public final String name;
        public final boolean enabled;
        public final Phase phase;
        public final boolean regex;
        public final String match;
        public final String replace;
        public final String urlContains; // optional filter

        public Rule(
                String id,
                String name,
                boolean enabled,
                Phase phase,
                boolean regex,
                String match,
                String replace,
                String urlContains) {
            this.id = id;
            this.name = name;
            this.enabled = enabled;
            this.phase = phase;
            this.regex = regex;
            this.match = match;
            this.replace = replace == null ? "" : replace;
            this.urlContains = urlContains;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = Json.obj();
            m.put("id", id);
            m.put("name", name);
            m.put("enabled", enabled);
            m.put("phase", phase.name());
            m.put("regex", regex);
            m.put("match", match);
            m.put("replace", replace);
            m.put("urlContains", urlContains);
            return m;
        }
    }

    private final MontoyaApi api;
    private final CopyOnWriteArrayList<Rule> rules = new CopyOnWriteArrayList<>();

    public RewriteEngine(MontoyaApi api) {
        this.api = api;
    }

    public List<Rule> listRules() {
        return new ArrayList<>(rules);
    }

    public Rule addRule(Map<String, Object> body) {
        String rawId = Json.str(body, "id");
        final String id =
                (rawId == null || rawId.isBlank())
                        ? UUID.randomUUID().toString().substring(0, 8)
                        : rawId;
        String name = Json.str(body, "name", "rule-" + id);
        boolean enabled = Json.bool(body, "enabled", true);
        String phaseStr = Json.str(body, "phase", "REQUEST");
        Phase phase = Phase.valueOf(phaseStr.trim().toUpperCase());
        boolean regex = Json.bool(body, "regex", false);
        String match = Json.str(body, "match");
        if (match == null || match.isEmpty()) {
            throw new IllegalArgumentException("match is required");
        }
        String replace = Json.str(body, "replace", "");
        String urlContains = Json.str(body, "urlContains");
        Rule rule = new Rule(id, name, enabled, phase, regex, match, replace, urlContains);
        // replace existing id
        rules.removeIf(r -> r.id.equals(id));
        rules.add(rule);
        return rule;
    }

    public boolean removeRule(String id) {
        return rules.removeIf(r -> r.id.equals(id));
    }

    public void clearRules() {
        rules.clear();
    }

    private boolean applies(Rule rule, String url, Phase current) {
        if (!rule.enabled) {
            return false;
        }
        if (rule.phase != Phase.BOTH && rule.phase != current) {
            return false;
        }
        if (rule.urlContains != null && !rule.urlContains.isBlank()) {
            if (url == null || !url.contains(rule.urlContains)) {
                return false;
            }
        }
        return true;
    }

    private String apply(String input, String url, Phase phase) {
        if (input == null || rules.isEmpty()) {
            return input;
        }
        String out = input;
        for (Rule rule : rules) {
            if (!applies(rule, url, phase)) {
                continue;
            }
            try {
                if (rule.regex) {
                    out = out.replaceAll(rule.match, rule.replace);
                } else {
                    out = out.replace(rule.match, rule.replace);
                }
            } catch (Exception e) {
                api.logging().logToError("Rewrite rule " + rule.id + " failed: " + e.getMessage());
            }
        }
        return out;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        HttpRequest req = interceptedRequest;
        String url = safeUrl(req);
        String raw = req.toString();
        String rewritten = apply(raw, url, Phase.REQUEST);
        if (rewritten.equals(raw)) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
        try {
            HttpRequest newReq = HttpRequest.httpRequest(req.httpService(), rewritten);
            return ProxyRequestToBeSentAction.continueWith(newReq);
        } catch (Exception e) {
            api.logging().logToError("Request rewrite failed: " + e.getMessage());
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        HttpResponse resp = interceptedResponse;
        String url = safeUrl(interceptedResponse.initiatingRequest());
        String raw = resp.toString();
        String rewritten = apply(raw, url, Phase.RESPONSE);
        if (rewritten.equals(raw)) {
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
        try {
            HttpResponse newResp = HttpResponse.httpResponse(rewritten);
            return ProxyResponseToBeSentAction.continueWith(newResp);
        } catch (Exception e) {
            api.logging().logToError("Response rewrite failed: " + e.getMessage());
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
    }

    private static String safeUrl(HttpRequest req) {
        try {
            return req.url();
        } catch (Exception e) {
            return "";
        }
    }
}
