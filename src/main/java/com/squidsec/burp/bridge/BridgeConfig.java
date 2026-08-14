package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

import java.util.UUID;

/**
 * HTTP bind settings and proxy-mirror options. Token is generated once and stored
 * in extension preferences (user-level).
 */
public final class BridgeConfig {

    public static final String PREF_PORT = "squidsec.bridge.port";
    public static final String PREF_TOKEN = "squidsec.bridge.token";
    public static final String PREF_HOST = "squidsec.bridge.host";
    public static final String PREF_SEND_VIA_PROXY = "squidsec.bridge.sendViaProxy";
    public static final String PREF_BURP_PROXY_HOST = "squidsec.bridge.burpProxyHost";
    public static final String PREF_BURP_PROXY_PORT = "squidsec.bridge.burpProxyPort";

    public static final String DEFAULT_HOST = "127.0.0.1";
    public static final String WSL_BIND_HOST = "0.0.0.0";
    public static final int DEFAULT_PORT = 9877;
    public static final String DEFAULT_BURP_PROXY_HOST = "127.0.0.1";
    public static final int DEFAULT_BURP_PROXY_PORT = 8080;

    private final String bindHost;
    private final int port;
    private final String token;
    private final boolean sendViaProxy;
    private final String burpProxyHost;
    private final int burpProxyPort;

    public BridgeConfig(String bindHost, int port, String token) {
        this(bindHost, port, token, true, DEFAULT_BURP_PROXY_HOST, DEFAULT_BURP_PROXY_PORT);
    }

    public BridgeConfig(
            String bindHost,
            int port,
            String token,
            boolean sendViaProxy,
            String burpProxyHost,
            int burpProxyPort) {
        this.bindHost = bindHost == null || bindHost.isBlank() ? DEFAULT_HOST : bindHost.trim();
        this.port = port <= 0 || port > 65535 ? DEFAULT_PORT : port;
        this.token = token == null ? "" : token;
        this.sendViaProxy = sendViaProxy;
        this.burpProxyHost =
                burpProxyHost == null || burpProxyHost.isBlank() ? DEFAULT_BURP_PROXY_HOST : burpProxyHost.trim();
        this.burpProxyPort = burpProxyPort <= 0 || burpProxyPort > 65535 ? DEFAULT_BURP_PROXY_PORT : burpProxyPort;
    }

    public String bindHost() {
        return bindHost;
    }

    public int port() {
        return port;
    }

    public String token() {
        return token;
    }

    public boolean sendViaProxy() {
        return sendViaProxy;
    }

    public String burpProxyHost() {
        return burpProxyHost;
    }

    public int burpProxyPort() {
        return burpProxyPort;
    }

    public boolean listensForWsl() {
        return WSL_BIND_HOST.equals(bindHost) || "*".equals(bindHost);
    }

    public BridgeConfig withBind(String host, int newPort) {
        return new BridgeConfig(host, newPort, token, sendViaProxy, burpProxyHost, burpProxyPort);
    }

    public BridgeConfig withSendViaProxy(boolean enabled, String proxyHost, int proxyPort) {
        return new BridgeConfig(bindHost, port, token, enabled, proxyHost, proxyPort);
    }

    public void save(Preferences prefs) {
        prefs.setString(PREF_HOST, bindHost);
        prefs.setInteger(PREF_PORT, port);
        prefs.setString(PREF_TOKEN, token);
        prefs.setInteger(PREF_SEND_VIA_PROXY, sendViaProxy ? 1 : 0);
        prefs.setString(PREF_BURP_PROXY_HOST, burpProxyHost);
        prefs.setInteger(PREF_BURP_PROXY_PORT, burpProxyPort);
    }

    public static BridgeConfig load(MontoyaApi api) {
        Preferences prefs = api.persistence().preferences();

        String host = prefs.getString(PREF_HOST);
        if (host == null || host.isBlank()) {
            host = DEFAULT_HOST;
            prefs.setString(PREF_HOST, host);
        }

        Integer port = prefs.getInteger(PREF_PORT);
        if (port == null || port <= 0 || port > 65535) {
            port = DEFAULT_PORT;
            prefs.setInteger(PREF_PORT, port);
        }

        String token = prefs.getString(PREF_TOKEN);
        if (token == null || token.isBlank()) {
            token = UUID.randomUUID().toString().replace("-", "");
            prefs.setString(PREF_TOKEN, token);
            api.logging().logToOutput("Generated AI Bridge API token. Copy it from the AI Bridge tab (not logged here).");
        } else {
            api.logging().logToOutput("AI Bridge API token is stored in extension preferences. Copy it from the AI Bridge tab.");
        }

        Integer via = prefs.getInteger(PREF_SEND_VIA_PROXY);
        boolean sendViaProxy = via == null || via != 0;

        String proxyHost = prefs.getString(PREF_BURP_PROXY_HOST);
        if (proxyHost == null || proxyHost.isBlank()) {
            proxyHost = DEFAULT_BURP_PROXY_HOST;
        }
        Integer proxyPort = prefs.getInteger(PREF_BURP_PROXY_PORT);
        if (proxyPort == null || proxyPort <= 0 || proxyPort > 65535) {
            proxyPort = DEFAULT_BURP_PROXY_PORT;
        }

        return new BridgeConfig(host, port, token, sendViaProxy, proxyHost, proxyPort);
    }
}
