package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

final class BridgeContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;

    BridgeContextMenu(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<HttpRequestResponse> selected = List.of();
        try {
            selected = event.selectedRequestResponses();
        } catch (Exception ignored) {
        }
        if (selected == null || selected.isEmpty()) {
            try {
                if (event.messageEditorRequestResponse().isPresent()) {
                    selected = List.of(event.messageEditorRequestResponse().get().requestResponse());
                }
            } catch (Exception ignored) {
            }
        }
        if (selected == null || selected.isEmpty()) {
            return items;
        }
        HttpRequestResponse rr = selected.get(0);
        JMenuItem curl = new JMenuItem("AI Bridge: copy as curl");
        curl.addActionListener(e -> {
            try {
                String raw = MessageCodec.requestRaw(rr.request(), true, 200_000);
                String url = "";
                try {
                    url = rr.request().url();
                } catch (Exception ignored) {
                }
                boolean https = rr.request().httpService() != null && rr.request().httpService().secure();
                Toolkit.getDefaultToolkit()
                        .getSystemClipboard()
                        .setContents(new StringSelection(EngagementTools.toCurl(raw, url, https)), null);
            } catch (Exception ex) {
                api.logging().logToError("copy curl failed: " + ex.getMessage());
            }
        });
        JMenuItem org = new JMenuItem("AI Bridge: send to Organizer");
        org.addActionListener(e -> {
            Thread t = new Thread(() -> {
                try {
                    api.organizer().sendToOrganizer(rr);
                } catch (Exception ex) {
                    api.logging().logToError("organizer send failed: " + ex.getMessage());
                }
            }, "ai-bridge-organizer");
            t.setDaemon(true);
            t.start();
        });
        items.add(curl);
        items.add(org);
        return items;
    }
}
