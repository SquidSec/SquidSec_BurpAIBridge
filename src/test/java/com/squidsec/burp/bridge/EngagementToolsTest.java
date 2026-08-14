package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EngagementToolsTest {

    @Test
    void curlAndRedact() {
        String raw = "POST /x HTTP/1.1\nHost: a.test\nAuthorization: Bearer secret\n\nname=1";
        String curl = EngagementTools.toCurl(raw, "https://a.test/x", true);
        assertTrue(curl.contains("curl -sk"));
        assertTrue(curl.contains("-X"));
        assertTrue(curl.contains("POST"));
        assertTrue(curl.contains("https://a.test/x"));
        assertTrue(EngagementTools.redact(raw).contains("[REDACTED]"));
        assertFalse(EngagementTools.redact(raw).contains("Bearer secret"));
    }

    @Test
    void findingStartsCorrectly() {
        String f = EngagementTools.findingDraft("IDOR - read other user", "https://t/x", "an IDOR on /x.", "GET /x", "HTTP/1.1 200", null);
        assertTrue(f.startsWith("IDOR - read other user"));
        assertTrue(f.contains("Our consultants identified"));
        assertTrue(f.contains("### Recommendation"));
    }

    @Test
    void endpointDedupe() {
        List<Map<String, Object>> rows = EngagementTools.endpointMap(
                List.of("GET https://h/users/12", "GET https://h/users/99", "POST https://h/users"));
        assertEquals(2, rows.size());
    }

    @Test
    void programJsonScope() {
        String json = "{\"targets\":[{\"asset\":\"https://app.example/\"},{\"asset\":\"*.api.example\"}]}";
        List<String> urls = EngagementTools.scopeUrlsFromProgramJson(json);
        assertTrue(urls.stream().anyMatch(u -> u.contains("app.example")));
        assertTrue(urls.stream().anyMatch(u -> u.contains("api.example")));
    }

    @Test
    void csrfAndDecode() {
        String html = EngagementTools.csrfPoc("https://t/x", "POST", Map.of("a", "1"));
        assertTrue(html.contains("action=\"https://t/x\""));
        assertTrue(html.contains("name=\"a\""));
        Map<String, Object> d = EngagementTools.decodeAll("a%20b");
        assertEquals("a b", d.get("urlDecoded"));
    }
}
