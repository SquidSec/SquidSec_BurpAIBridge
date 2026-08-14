package com.squidsec.burp.bridge;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessageCodecTest {

    @BeforeAll
    static void factory() {
        MockMontoyaApi.installObjectFactory();
    }

    @Test
    void buildRequestRequiresRaw() {
        assertThrows(IllegalArgumentException.class, () -> MessageCodec.buildRequest(Map.of()));
    }

    @Test
    void buildRequestFromRawAndHost() {
        Map<String, Object> body = Json.obj();
        body.put("raw", "GET /x HTTP/1.1\r\nHost: t.example\r\n\r\n");
        body.put("host", "t.example");
        body.put("port", 443);
        body.put("https", true);
        HttpRequest req = MessageCodec.buildRequest(body);
        assertEquals("GET", req.method());
        assertTrue(req.url().contains("t.example") || "/x".equals(req.path()) || req.path().contains("/x"));
    }

    @Test
    void requestToJsonIncludesMethod() {
        HttpRequest req = MockMontoyaApi.fakeRequest("GET", "https://example.com/a", "example.com", 443, true, "");
        Map<String, Object> json = MessageCodec.requestToJson(req, true, 1000);
        assertEquals("GET", json.get("method"));
        assertTrue(json.containsKey("url") || json.containsKey("raw") || json.containsKey("path"));
    }
}
