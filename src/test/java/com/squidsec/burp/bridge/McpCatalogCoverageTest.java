package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpCatalogCoverageTest {

    @Test
    void everyCatalogToolHasARoute() {
        Set<String> names = McpCatalog.tools().stream()
                .map(t -> String.valueOf(t.get("name")))
                .collect(Collectors.toSet());
        assertTrue(names.size() >= 30);
        java.util.Map<String, Object> args = new java.util.LinkedHashMap<>();
        args.put("url", "https://t/");
        args.put("raw", "GET / HTTP/1.1");
        args.put("path", "/tmp/x");
        args.put("json", "{}");
        args.put("input", "a");
        args.put("data", "x");
        args.put("text", "hi");
        args.put("lines", "GET https://t/");
        args.put("contains", "a");
        args.put("title", "T");
        args.put("keywords", "a");
        args.put("responses", "HTTP/1.1 200");
        for (String name : names) {
            assertNotNull(McpToolRoutes.map(name, args), name);
        }
    }

    @Test
    void requiredFieldsMarked() {
        var send = McpCatalog.tools().stream().filter(t -> "burp_http_send".equals(t.get("name"))).findFirst().orElseThrow();
        @SuppressWarnings("unchecked")
        var schema = (java.util.Map<String, Object>) send.get("inputSchema");
        assertTrue(schema.containsKey("required"));
        assertEquals("object", schema.get("type"));
    }
}
