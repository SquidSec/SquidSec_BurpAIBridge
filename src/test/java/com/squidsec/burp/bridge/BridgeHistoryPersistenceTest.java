package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BridgeHistoryPersistenceTest {

    @Test
    void roundTripProjectData() {
        MockMontoyaApi mock = MockMontoyaApi.create();
        BridgeHistoryLog log = new BridgeHistoryLog();
        log.add(new BridgeLogEntry(
                3,
                Instant.parse("2026-08-14T12:00:00Z"),
                "127.0.0.1",
                "GET",
                "/x",
                "a=1",
                "https://t.example/x?a=1",
                "t.example",
                443,
                true,
                200,
                12,
                "GET /x HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\nok"));
        log.nextId();
        log.nextId();
        log.nextId();

        BridgeHistoryPersistence.save(mock.api.persistence().extensionData(), log);

        BridgeHistoryLog loaded = new BridgeHistoryLog();
        BridgeHistoryPersistence.loadInto(mock.api.persistence().extensionData(), loaded);
        assertEquals(1, loaded.size());
        BridgeLogEntry e = loaded.snapshot().get(0);
        assertEquals(3, e.id());
        assertEquals("GET", e.method());
        assertEquals("https://t.example/x?a=1", e.displayUrl());
        assertEquals(200, e.status());
        assertTrue(e.requestRaw().contains("GET /x"));
        assertTrue(loaded.peekId() >= 3);
    }
}
