package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AbsoluteProxyRequestTest {

    @Test
    void rewriteUsesAbsoluteForm() {
        String raw = "GET /login HTTP/1.1\r\nHost: app.example\r\n\r\n";
        String out = AbsoluteProxyRequest.rewriteRaw("GET", "https://app.example/login", raw);
        assertTrue(out.startsWith("GET https://app.example/login HTTP/1.1"));
        assertTrue(out.contains("Host: app.example"));
    }

    @Test
    void rewriteKeepsBody() {
        String raw = "POST /x HTTP/1.1\r\nHost: h\r\n\r\nname=1";
        String out = AbsoluteProxyRequest.rewriteRaw("POST", "http://h/x", raw);
        assertTrue(out.startsWith("POST http://h/x HTTP/1.1"));
        assertTrue(out.endsWith("name=1"));
    }
}
