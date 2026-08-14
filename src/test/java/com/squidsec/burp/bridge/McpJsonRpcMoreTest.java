package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpJsonRpcMoreTest {

    @Test
    void initializeAndPingAndUnknown() {
        Map<String, Object> init = Json.obj();
        init.put("jsonrpc", "2.0");
        init.put("id", 1);
        init.put("method", "initialize");
        Map<String, Object> params = Json.obj();
        params.put("protocolVersion", "2025-06-18");
        init.put("params", params);
        Map<String, Object> reply = McpJsonRpc.handle(init, false, (n, a) -> Map.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) reply.get("result");
        assertEquals("2025-06-18", result.get("protocolVersion"));

        Map<String, Object> ping = Json.obj();
        ping.put("jsonrpc", "2.0");
        ping.put("id", 2);
        ping.put("method", "ping");
        assertTrue(McpJsonRpc.handle(ping, true, (n, a) -> Map.of()).containsKey("result"));

        Map<String, Object> unk = Json.obj();
        unk.put("jsonrpc", "2.0");
        unk.put("id", 3);
        unk.put("method", "nope");
        assertTrue(McpJsonRpc.handle(unk, true, (n, a) -> Map.of()).containsKey("error"));
    }

    @Test
    void toolResultMarksMapErrors() {
        Map<String, Object> payload = Json.obj();
        payload.put("error", "bad");
        assertTrue(McpJsonRpc.isError(payload));
        Map<String, Object> wrapped = McpJsonRpc.toolResult(payload, true);
        assertEquals(true, wrapped.get("isError"));
    }
}
