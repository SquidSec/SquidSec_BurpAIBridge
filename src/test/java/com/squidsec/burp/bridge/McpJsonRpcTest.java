package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpJsonRpcTest {

    @Test
    void toolsListDoesNotNeedAuth() {
        Map<String, Object> msg = Json.obj();
        msg.put("jsonrpc", "2.0");
        msg.put("id", 1);
        msg.put("method", "tools/list");
        Map<String, Object> reply = McpJsonRpc.handle(msg, false, (n, a) -> Map.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) reply.get("result");
        assertTrue(result.containsKey("tools"));
    }

    @Test
    void toolsCallRequiresAuth() {
        Map<String, Object> msg = Json.obj();
        msg.put("jsonrpc", "2.0");
        msg.put("id", 2);
        msg.put("method", "tools/call");
        Map<String, Object> params = Json.obj();
        params.put("name", "burp_bridge_health");
        msg.put("params", params);
        Map<String, Object> denied = McpJsonRpc.handle(msg, false, (n, a) -> Map.of("ok", true));
        assertTrue(denied.containsKey("error"));

        Map<String, Object> ok = McpJsonRpc.handle(msg, true, (n, a) -> {
            assertEquals("burp_bridge_health", n);
            return Map.of("ok", true);
        });
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) ok.get("result");
        assertFalse((Boolean) result.get("isError"));
    }

    @Test
    void initializedNotificationHasNoReply() {
        Map<String, Object> msg = Json.obj();
        msg.put("jsonrpc", "2.0");
        msg.put("method", "notifications/initialized");
        assertNull(McpJsonRpc.handle(msg, true, (n, a) -> Map.of()));
    }
}
