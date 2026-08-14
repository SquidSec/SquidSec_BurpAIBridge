package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EngagementToolsMoreTest {

    @Test
    void redactCookiesAndTokens() {
        String raw = "GET / HTTP/1.1\nCookie: sid=abc\nX-CSRF-Token: zzz\n\npassword=hunter2&access_token=aaa";
        String out = EngagementTools.redact(raw);
        assertTrue(out.contains("[REDACTED]"));
        assertTrue(!out.contains("hunter2") || out.contains("password=[REDACTED]"));
    }

    @Test
    void emptyAndWildcardAssets() {
        assertEquals("", EngagementTools.toCurl("", null, true));
        List<String> urls = EngagementTools.scopeUrlsFromProgramJson(
                "{\"assets\":[\"example.com\",\"https://app.example/path\"]}");
        assertTrue(urls.stream().anyMatch(u -> u.contains("example.com") || u.contains("app.example")));
        assertEquals("https://x.test/", EngagementTools.normalizeAsset("x.test"));
        assertEquals("https://api.x/", EngagementTools.normalizeAsset("*.api.x"));
    }

    @Test
    void findingForcesPrefix() {
        String f = EngagementTools.findingDraft("XSS - reflected", "https://t/", "reflected XSS.", "GET /", "200", "Fix it.");
        assertTrue(f.contains("Our consultants identified reflected XSS."));
        assertTrue(f.contains("Fix it."));
    }

    @Test
    void endpointIgnoresBlank() {
        assertTrue(EngagementTools.endpointMap(List.of("", "  ")).isEmpty());
        assertEquals(1, EngagementTools.endpointMap(List.of("https://h/a")).size());
    }

    @Test
    void decodeBase64AndHtml() {
        String b64 = java.util.Base64.getEncoder().encodeToString("hi".getBytes());
        Map<String, Object> d = EngagementTools.decodeAll(b64);
        assertEquals("hi", d.get("base64"));
        assertEquals("<x>", EngagementTools.decodeAll("&lt;x&gt;").get("htmlUnescaped"));
    }
}
