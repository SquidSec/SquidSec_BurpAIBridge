package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WslEndpointTest {

    @TempDir
    Path tmp;

    @Test
    void writesJsonFile() throws Exception {
        BridgeConfig cfg = new BridgeConfig("0.0.0.0", 9877, "tok");
        Path out = tmp.resolve("burp-ai-bridge.json");
        WslEndpoint.write(out, cfg, 9877);
        String json = Files.readString(out);
        Map<String, Object> m = Json.asObject(Json.parse(json));
        assertEquals("tok", Json.str(m, "token"));
        assertEquals(9877, Json.integer(m, "port", 0));
        assertEquals("http://127.0.0.1:9877", Json.str(m, "baseUrl"));
        assertTrue(Json.bool(m, "wslListenAll", false));
        assertTrue(Json.str(m, "wslHint", "").contains("BURP_BRIDGE_BASE"));
    }
}
