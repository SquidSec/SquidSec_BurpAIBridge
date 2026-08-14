package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTest {

    @Test
    void roundTripObjectArrayAndEscapes() {
        Map<String, Object> m = Json.obj();
        m.put("s", "a\"b\\c");
        m.put("n", 42);
        m.put("b", true);
        m.put("z", null);
        List<Object> arr = Json.arr();
        arr.add("x");
        arr.add(1);
        m.put("a", arr);
        String json = Json.stringify(m);
        Map<String, Object> back = Json.asObject(Json.parse(json));
        assertEquals("a\"b\\c", Json.str(back, "s"));
        assertEquals(42, Json.integer(back, "n", 0));
        assertTrue(Json.bool(back, "b", false));
        assertEquals("x", Json.asArray(back.get("a")).get(0));
    }

    @Test
    void helpersDefaultOnMissing() {
        Map<String, Object> m = Json.obj();
        assertEquals("d", Json.str(m, "no", "d"));
        assertEquals(7, Json.integer(m, "no", 7));
        assertFalse(Json.bool(m, "no", false));
        assertThrows(IllegalArgumentException.class, () -> Json.asObject("nope"));
        assertThrows(IllegalArgumentException.class, () -> Json.asArray(Json.obj()));
    }

    @Test
    void parsesLongNumbers() {
        Object n = Json.parse("1700000000000");
        assertTrue(n instanceof Long || n instanceof Integer);
    }
}
