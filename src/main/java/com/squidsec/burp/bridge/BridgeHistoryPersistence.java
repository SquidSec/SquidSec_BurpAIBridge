package com.squidsec.burp.bridge;

import burp.api.montoya.persistence.PersistedObject;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Project-scoped save/load of the AI Bridge history table. */
public final class BridgeHistoryPersistence {

    public static final String KEY_JSON = "squidsec.bridge.history.v1";
    public static final String KEY_SEQ = "squidsec.bridge.history.seq";
    public static final int MAX_STORED = 400;

    private BridgeHistoryPersistence() {}

    public static void save(PersistedObject data, BridgeHistoryLog log) {
        if (data == null || log == null) {
            return;
        }
        List<BridgeLogEntry> snap = log.snapshot();
        int from = Math.max(0, snap.size() - MAX_STORED);
        List<Object> arr = Json.arr();
        for (int i = from; i < snap.size(); i++) {
            arr.add(toMap(snap.get(i)));
        }
        data.setString(KEY_JSON, Json.stringify(arr));
        data.setInteger(KEY_SEQ, (int) Math.min(Integer.MAX_VALUE, log.peekId()));
    }

    public static void loadInto(PersistedObject data, BridgeHistoryLog log) {
        if (data == null || log == null) {
            return;
        }
        String json = data.getString(KEY_JSON);
        Integer seq = data.getInteger(KEY_SEQ);
        List<BridgeLogEntry> restored = parseEntries(json);
        long seqVal = seq == null ? 0L : seq.longValue();
        for (BridgeLogEntry e : restored) {
            if (e.id() > seqVal) {
                seqVal = e.id();
            }
        }
        log.restore(restored, seqVal);
    }

    public static List<BridgeLogEntry> parseEntries(String json) {
        List<BridgeLogEntry> out = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return out;
        }
        Object parsed = Json.parse(json);
        List<Object> arr;
        try {
            arr = Json.asArray(parsed);
        } catch (IllegalArgumentException e) {
            return out;
        }
        for (Object o : arr) {
            if (!(o instanceof Map<?, ?> raw)) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) raw;
            out.add(fromMap(m));
        }
        return out;
    }

    static Map<String, Object> toMap(BridgeLogEntry e) {
        Map<String, Object> m = Json.obj();
        m.put("id", e.id());
        m.put("time", e.time().toEpochMilli());
        m.put("client", e.client());
        m.put("method", e.method());
        m.put("path", e.path());
        m.put("query", e.query());
        m.put("url", e.displayUrl());
        m.put("host", e.host());
        m.put("port", e.port());
        m.put("https", e.https());
        m.put("status", e.status());
        m.put("durationMs", e.durationMs());
        m.put("requestRaw", e.requestRaw());
        m.put("responseRaw", e.responseRaw());
        return m;
    }

    static BridgeLogEntry fromMap(Map<String, Object> m) {
        long id = Json.integer(m, "id", 0);
        long timeMs = 0L;
        Object t = m.get("time");
        if (t instanceof Number n) {
            timeMs = n.longValue();
        } else if (t != null) {
            try {
                timeMs = Long.parseLong(String.valueOf(t));
            } catch (NumberFormatException ignored) {
            }
        }
        Instant time = timeMs > 0 ? Instant.ofEpochMilli(timeMs) : Instant.EPOCH;
        return new BridgeLogEntry(
                id,
                time,
                Json.str(m, "client", ""),
                Json.str(m, "method", ""),
                Json.str(m, "path", "/"),
                Json.str(m, "query", ""),
                Json.str(m, "url", ""),
                Json.str(m, "host", ""),
                Json.integer(m, "port", 0),
                Json.bool(m, "https", false),
                Json.integer(m, "status", 0),
                duration(m),
                Json.str(m, "requestRaw", ""),
                Json.str(m, "responseRaw", ""));
    }

    private static long duration(Map<String, Object> m) {
        Object v = m.get("durationMs");
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Json.integer(m, "durationMs", 0);
    }
}
