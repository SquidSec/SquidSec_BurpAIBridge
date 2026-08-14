package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BridgeHistoryLogTest {

    @Test
    void idsAndCapAndListeners() {
        BridgeHistoryLog log = new BridgeHistoryLog(100);
        AtomicInteger adds = new AtomicInteger();
        AtomicInteger clears = new AtomicInteger();
        log.addListener(new BridgeHistoryLog.Listener() {
            @Override
            public void onEntry(BridgeLogEntry entry) {
                adds.incrementAndGet();
            }

            @Override
            public void onCleared() {
                clears.incrementAndGet();
            }
        });
        assertEquals(1, log.nextId());
        log.add(entry(1));
        log.add(entry(2));
        assertEquals(2, log.size());
        assertEquals(2, adds.get());
        log.clear();
        assertEquals(0, log.size());
        assertEquals(1, clears.get());
    }

    @Test
    void restoreSetsSeq() {
        BridgeHistoryLog log = new BridgeHistoryLog();
        log.restore(List.of(entry(9)), 9);
        assertEquals(1, log.size());
        assertEquals(9, log.peekId());
        assertEquals(10, log.nextId());
    }

    @Test
    void evictsOldestWhenOverMax() {
        BridgeHistoryLog log = new BridgeHistoryLog(100);
        for (int i = 0; i < 120; i++) {
            log.add(entry(i + 1));
        }
        assertTrue(log.size() <= 100);
        assertEquals(120, log.snapshot().get(log.size() - 1).id());
    }

    private static BridgeLogEntry entry(long id) {
        return new BridgeLogEntry(
                id, Instant.EPOCH, "c", "GET", "/", "", "https://t/", "t", 443, true, 200, 1, "GET /", "HTTP/1.1 200");
    }
}
