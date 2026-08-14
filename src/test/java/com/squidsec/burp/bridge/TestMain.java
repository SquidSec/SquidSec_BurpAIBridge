package com.squidsec.burp.bridge;

/**
 * Standalone entrypoint: run the AI Bridge HTTP server against a mock Burp API.
 *
 *   ./gradlew testMain
 *
 * Then:
 *   curl http://127.0.0.1:9877/health
 *   curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9877/proxy/history
 */
public final class TestMain {

    public static void main(String[] args) throws Exception {
        MockMontoyaApi mock = MockMontoyaApi.create();

        // Force deterministic token/port for local debugging (overrides prefs)
        mock.stringPrefs.put(BridgeConfig.PREF_HOST, "127.0.0.1");
        mock.intPrefs.put(BridgeConfig.PREF_PORT, 9877);
        mock.stringPrefs.put(BridgeConfig.PREF_TOKEN, "test-token-debug");

        BridgeConfig config = BridgeConfig.load(mock.api);
        RewriteEngine rewriteEngine = new RewriteEngine(mock.api);
        BridgeHistoryLog historyLog = new BridgeHistoryLog();

        BridgeHttpServer server = new BridgeHttpServer(mock.api, config, rewriteEngine, historyLog);
        server.start();

        System.out.println();
        System.out.println("=== SquidSec Burp AI Bridge (MOCK MODE) ===");
        System.out.println("Listening: http://" + config.bindHost() + ":" + config.port());
        System.out.println("Token:     " + config.token());
        System.out.println("Health:    curl http://" + config.bindHost() + ":" + config.port() + "/health");
        System.out.println(
                "History:   curl -H \"Authorization: Bearer "
                        + config.token()
                        + "\" http://"
                        + config.bindHost()
                        + ":"
                        + config.port()
                        + "/proxy/history");
        System.out.println("Sample history items: " + mock.history.size());
        System.out.println("Ctrl+C to stop.");
        System.out.println();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop();
            System.out.println("Mock bridge stopped.");
        }));

        Thread.currentThread().join();
    }
}
