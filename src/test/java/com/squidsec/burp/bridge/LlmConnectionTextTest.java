package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class LlmConnectionTextTest {

    @Test
    void includesTokenUrlsAndWsl() {
        BridgeConfig cfg = new BridgeConfig("0.0.0.0", 9877, "tok123");
        String text = LlmConnectionText.build(cfg, 9877);
        assertTrue(text.contains("tok123"));
        assertTrue(text.contains("http://127.0.0.1:9877"));
        assertTrue(text.contains("BURP_BRIDGE_TOKEN=tok123"));
        assertTrue(text.contains("0.0.0.0"));
        assertTrue(text.contains("/http/send"));
        assertTrue(text.contains("nameserver"));
    }
}
