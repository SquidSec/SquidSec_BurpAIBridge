package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class McpCatalogTest {

    @Test
    void toolsHaveNameDescriptionAndSchema() {
        List<Map<String, Object>> tools = McpCatalog.tools();
        assertTrue(tools.size() >= 16);
        Set<String> names = tools.stream().map(t -> String.valueOf(t.get("name"))).collect(Collectors.toSet());
        assertTrue(names.contains("burp_http_send"));
        assertTrue(names.contains("burp_proxy_history"));
        assertTrue(names.contains("burp_scope_check"));
        for (Map<String, Object> t : tools) {
            assertTrue(t.get("description") instanceof String);
            assertTrue(t.get("inputSchema") instanceof Map);
        }
    }

    @Test
    void initializeAdvertisesToolsCapability() {
        Map<String, Object> init = McpCatalog.initializeResult("2025-06-18");
        assertEquals("2025-06-18", init.get("protocolVersion"));
        @SuppressWarnings("unchecked")
        Map<String, Object> info = (Map<String, Object>) init.get("serverInfo");
        assertEquals("burp-ai-bridge", info.get("name"));
    }
}
