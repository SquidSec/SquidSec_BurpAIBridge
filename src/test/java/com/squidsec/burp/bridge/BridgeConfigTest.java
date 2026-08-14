package com.squidsec.burp.bridge;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BridgeConfigTest {

    @Test
    void loadAndSaveHostPort() {
        MockMontoyaApi mock = MockMontoyaApi.create();
        mock.stringPrefs.put(BridgeConfig.PREF_HOST, "0.0.0.0");
        mock.intPrefs.put(BridgeConfig.PREF_PORT, 9911);
        mock.stringPrefs.put(BridgeConfig.PREF_TOKEN, "abc");
        mock.intPrefs.put(BridgeConfig.PREF_SEND_VIA_PROXY, 1);
        mock.stringPrefs.put(BridgeConfig.PREF_BURP_PROXY_HOST, "127.0.0.1");
        mock.intPrefs.put(BridgeConfig.PREF_BURP_PROXY_PORT, 8080);

        BridgeConfig cfg = BridgeConfig.load(mock.api);
        assertEquals("0.0.0.0", cfg.bindHost());
        assertEquals(9911, cfg.port());
        assertTrue(cfg.listensForWsl());
        assertTrue(cfg.sendViaProxy());

        BridgeConfig next = cfg.withBind("127.0.0.1", 9877).withSendViaProxy(false, "127.0.0.1", 8081);
        next.save(mock.api.persistence().preferences());
        assertEquals("127.0.0.1", mock.stringPrefs.get(BridgeConfig.PREF_HOST));
        assertEquals(9877, mock.intPrefs.get(BridgeConfig.PREF_PORT));
        assertEquals(0, mock.intPrefs.get(BridgeConfig.PREF_SEND_VIA_PROXY));
        assertEquals(8081, mock.intPrefs.get(BridgeConfig.PREF_BURP_PROXY_PORT));

        BridgeConfig reloaded = BridgeConfig.load(mock.api);
        assertFalse(reloaded.sendViaProxy());
        assertEquals(8081, reloaded.burpProxyPort());
    }
}
