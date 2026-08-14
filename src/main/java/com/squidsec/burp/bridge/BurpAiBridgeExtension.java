package com.squidsec.burp.bridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.persistence.PersistedObject;

/**
 * SquidSec Burp AI Bridge — local HTTP API for Grok/MCP clients.
 */
public class BurpAiBridgeExtension implements BurpExtension {

    private BridgeHttpServer server;
    private RewriteEngine rewriteEngine;
    private BridgeHistoryLog historyLog;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SquidSec Burp AI Bridge");

        BridgeConfig config = BridgeConfig.load(api);
        historyLog = new BridgeHistoryLog();
        PersistedObject projectData = api.persistence().extensionData();
        try {
            BridgeHistoryPersistence.loadInto(projectData, historyLog);
        } catch (Exception e) {
            api.logging().logToError("AI Bridge history restore failed: " + e.getMessage());
        }
        historyLog.addListener(new BridgeHistoryLog.Listener() {
            @Override
            public void onEntry(BridgeLogEntry entry) {
                try {
                    BridgeHistoryPersistence.save(projectData, historyLog);
                } catch (Exception ignored) {
                }
            }

            @Override
            public void onCleared() {
                try {
                    BridgeHistoryPersistence.save(projectData, historyLog);
                } catch (Exception ignored) {
                }
            }
        });

        rewriteEngine = new RewriteEngine(api);
        api.proxy().registerRequestHandler(rewriteEngine);
        api.proxy().registerResponseHandler(rewriteEngine);

        try {
            server = new BridgeHttpServer(api, config, rewriteEngine, historyLog);
            server.start();

            try {
                WslEndpoint.write(config, server.boundPort());
            } catch (Exception e) {
                api.logging().logToError("AI Bridge endpoint file not written: " + e.getMessage());
            }

            BridgeHistoryTab tab = new BridgeHistoryTab(api, historyLog, server);
            api.userInterface().registerSuiteTab("AI Bridge", tab);
            try {
                api.userInterface().registerContextMenuItemsProvider(new BridgeContextMenu(api));
            } catch (Exception e) {
                api.logging().logToError("AI Bridge context menu not registered: " + e.getMessage());
            }

            api.logging().logToOutput(
                    "SquidSec Burp AI Bridge v"
                            + BridgeVersion.VERSION
                            + " listening on http://"
                            + config.bindHost()
                            + ":"
                            + server.boundPort()
                            + " (token "
                            + (config.token().isBlank() ? "disabled" : "required")
                            + ")");
            api.logging().logToOutput("Suite tab: AI Bridge (API request history)");
            api.logging().logToOutput("Health: GET /health");
            api.logging().logToOutput("API docs: GET /");
            api.logging().logToOutput("WSL endpoint file: " + WslEndpoint.defaultPath());
        } catch (Exception e) {
            api.logging().logToError("Failed to start AI Bridge server: " + e.getMessage());
            e.printStackTrace(api.logging().error());
        }

        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                try {
                    BridgeHistoryPersistence.save(api.persistence().extensionData(), historyLog);
                } catch (Exception ignored) {
                }
                if (server != null) {
                    server.stop();
                }
                api.logging().logToOutput("SquidSec Burp AI Bridge stopped.");
            }
        });
    }
}
