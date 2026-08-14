package com.squidsec.burp.bridge;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpHttpTest {

    private BridgeHttpServer server;
    private String base;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void start() throws Exception {
        MockMontoyaApi mock = MockMontoyaApi.create();
        mock.stringPrefs.put(BridgeConfig.PREF_HOST, "127.0.0.1");
        mock.intPrefs.put(BridgeConfig.PREF_PORT, 19877);
        mock.stringPrefs.put(BridgeConfig.PREF_TOKEN, "test-token-debug");
        BridgeConfig config = BridgeConfig.load(mock.api);
        server = new BridgeHttpServer(mock.api, config, new RewriteEngine(mock.api), new BridgeHistoryLog());
        server.start();
        base = "http://127.0.0.1:" + server.boundPort();
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void discoverToolsWithoutAuth() throws Exception {
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create(base + "/mcp/tools")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        Map<String, Object> body = Json.asObject(Json.parse(resp.body()));
        assertTrue(body.containsKey("tools"));
        assertEquals("mcp", body.get("protocol"));
    }

    @Test
    void jsonRpcToolsList() throws Exception {
        String payload = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create(base + "/mcp"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(payload))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        Map<String, Object> body = Json.asObject(Json.parse(resp.body()));
        assertEquals("2.0", body.get("jsonrpc"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) body.get("result");
        assertTrue(result.containsKey("tools"));
    }

    @Test
    void callHealthWithToken() throws Exception {
        String payload = "{\"name\":\"burp_bridge_health\",\"arguments\":{}}";
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create(base + "/mcp/call"))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer test-token-debug")
                        .POST(HttpRequest.BodyPublishers.ofString(payload))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        Map<String, Object> body = Json.asObject(Json.parse(resp.body()));
        assertEquals(false, body.get("isError"));
        assertTrue(String.valueOf(body.get("content")).contains("SquidSec"));
    }
}
