package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpToolRoutesTest {

    @Test
    void mapsKnownTools() {
        assertEquals("/health", McpToolRoutes.map("burp_bridge_health", Map.of()).path);
        assertEquals("GET", McpToolRoutes.map("burp_scope_check", Map.of("url", "https://a")).method);
        assertEquals("https://a", McpToolRoutes.map("burp_scope_check", Map.of("url", "https://a")).query.get("url"));
        assertEquals("/http/send", McpToolRoutes.map("burp_http_send", Map.of("raw", "GET / HTTP/1.1")).path);
        assertEquals("POST", McpToolRoutes.map("burp_http_send", Map.of("raw", "GET / HTTP/1.1")).method);
        assertTrue(McpToolRoutes.map("burp_proxy_history", Map.of("inScope", true)).query.containsKey("inScopeOnly"));
        assertNull(McpToolRoutes.map("nope", Map.of()));
    }
}
