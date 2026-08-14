package com.squidsec.burp.bridge;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Writes a small JSON file Windows and WSL can both read. */
public final class WslEndpoint {

    private WslEndpoint() {}

    public static Path defaultPath() {
        return Path.of(System.getProperty("user.home"), ".squidsec", "burp-ai-bridge.json");
    }

    public static String toJson(BridgeConfig config, int boundPort) {
        int port = boundPort > 0 ? boundPort : config.port();
        Map<String, Object> m = Json.obj();
        m.put("version", BridgeVersion.VERSION);
        m.put("bindHost", config.bindHost());
        m.put("port", port);
        m.put("token", config.token());
        m.put("baseUrl", "http://127.0.0.1:" + port);
        m.put("mcpToolsUrl", "http://127.0.0.1:" + port + "/mcp/tools");
        m.put("mcpRpcUrl", "http://127.0.0.1:" + port + "/mcp");
        m.put("wslListenAll", config.listensForWsl());
        m.put("sendViaProxy", config.sendViaProxy());
        m.put("burpProxyHost", config.burpProxyHost());
        m.put("burpProxyPort", config.burpProxyPort());
        m.put(
                "wslHint",
                "export BURP_BRIDGE_BASE=http://127.0.0.1:"
                        + port
                        + "; export BURP_BRIDGE_TOKEN="
                        + config.token()
                        + "; if curl -fsS \"$BURP_BRIDGE_BASE/health\" >/dev/null; then :; else "
                        + "WINIP=$(grep nameserver /etc/resolv.conf | awk '{print $2}'); "
                        + "export BURP_BRIDGE_BASE=http://$WINIP:"
                        + port
                        + "; fi");
        return Json.stringify(m);
    }

    public static Path write(BridgeConfig config, int boundPort) throws IOException {
        return write(defaultPath(), config, boundPort);
    }

    public static Path write(Path path, BridgeConfig config, int boundPort) throws IOException {
        Files.createDirectories(path.getParent());
        Files.writeString(path, toJson(config, boundPort), StandardCharsets.UTF_8);
        return path;
    }
}
