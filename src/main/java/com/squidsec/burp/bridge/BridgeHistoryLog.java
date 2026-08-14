package com.squidsec.burp.bridge;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/** Thread-safe in-memory log of AI Bridge API traffic. */
public final class BridgeHistoryLog {

    public interface Listener {
        void onEntry(BridgeLogEntry entry);

        void onCleared();
    }

    private static final int DEFAULT_MAX = 5000;

    private final int maxEntries;
    private final AtomicLong seq = new AtomicLong(0);
    private final CopyOnWriteArrayList<BridgeLogEntry> entries = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public BridgeHistoryLog() {
        this(DEFAULT_MAX);
    }

    public BridgeHistoryLog(int maxEntries) {
        this.maxEntries = Math.max(100, maxEntries);
    }

    public long nextId() {
        return seq.incrementAndGet();
    }

    public long peekId() {
        return seq.get();
    }

    public void restore(List<BridgeLogEntry> restored, long seqValue) {
        entries.clear();
        if (restored != null) {
            entries.addAll(restored);
        }
        seq.set(Math.max(0L, seqValue));
    }

    public void add(BridgeLogEntry entry) {
        entries.add(entry);
        while (entries.size() > maxEntries) {
            entries.remove(0);
        }
        for (Listener l : listeners) {
            try {
                l.onEntry(entry);
            } catch (Exception ignored) {
            }
        }
    }

    public void clear() {
        entries.clear();
        for (Listener l : listeners) {
            try {
                l.onCleared();
            } catch (Exception ignored) {
            }
        }
    }

    public List<BridgeLogEntry> snapshot() {
        return new ArrayList<>(entries);
    }

    public int size() {
        return entries.size();
    }

    public void addListener(Listener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }
}
