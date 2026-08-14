package com.squidsec.burp.bridge;

import burp.api.montoya.MontoyaApi;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.RowSorter;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Suite tab: history of AI Bridge API requests/responses (proxy-history style).
 */
public final class BridgeHistoryTab extends JPanel implements BridgeHistoryLog.Listener {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final BridgeHistoryLog log;
    private final HistoryTableModel model;
    private final JTable table;
    private final TableRowSorter<HistoryTableModel> sorter;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JLabel statusLabel;
    private final JCheckBox autoScroll;
    private final JTextField filterField;
    private final JTextField hostField;
    private final JTextField portField;
    private final JCheckBox wslListen;
    private final JCheckBox sendViaProxy;
    private final JTextField burpProxyField;
    private final MontoyaApi api;
    private final BridgeHttpServer server;
    private final java.awt.Component dialogParent;

    public BridgeHistoryTab(MontoyaApi api, BridgeHistoryLog log, BridgeHttpServer server) {
        super(new BorderLayout(0, 0));
        this.api = api;
        this.log = log;
        this.server = server;
        java.awt.Component parent = this;
        try {
            parent = api.userInterface().swingUtils().suiteFrame();
        } catch (Exception ignored) {
        }
        this.dialogParent = parent == null ? this : parent;

        UserInterface ui = api.userInterface();
        requestEditor = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

        model = new HistoryTableModel();
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(false);
        sorter = new TableRowSorter<>(model);
        sorter.setSortKeys(List.of(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
        sorter.setSortsOnUpdates(true);
        table.setRowSorter(sorter);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        setColumnWidths();

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(ev -> log.clear());
        JButton copyLlm = new JButton("Copy LLM connection info");
        copyLlm.addActionListener(ev -> copyLlmInfo());
        autoScroll = new JCheckBox("Auto-select latest", true);
        left.add(clearBtn);
        left.add(copyLlm);
        left.add(autoScroll);
        left.add(new JLabel("Filter:"));
        filterField = new JTextField(24);
        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                applyFilter();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                applyFilter();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                applyFilter();
            }
        });
        left.add(filterField);
        statusLabel = new JLabel("0 entries");
        left.add(statusLabel);

        BridgeConfig cfg = server.config();
        JPanel settings = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        settings.add(new JLabel("Listen host:"));
        hostField = new JTextField(cfg.bindHost(), 12);
        settings.add(hostField);
        settings.add(new JLabel("Port:"));
        portField = new JTextField(String.valueOf(server.boundPort()), 6);
        settings.add(portField);
        wslListen = new JCheckBox("Listen on all interfaces (WSL)", cfg.listensForWsl());
        wslListen.addActionListener(ev -> {
            if (wslListen.isSelected()) {
                hostField.setText(BridgeConfig.WSL_BIND_HOST);
            } else if (BridgeConfig.WSL_BIND_HOST.equals(hostField.getText().trim())) {
                hostField.setText(BridgeConfig.DEFAULT_HOST);
            }
        });
        settings.add(wslListen);
        sendViaProxy = new JCheckBox("Send /http/send via Burp proxy", cfg.sendViaProxy());
        settings.add(sendViaProxy);
        settings.add(new JLabel("Burp proxy:"));
        burpProxyField = new JTextField(cfg.burpProxyHost() + ":" + cfg.burpProxyPort(), 14);
        settings.add(burpProxyField);
        JButton apply = new JButton("Apply listen settings");
        apply.addActionListener(ev -> applySettings());
        settings.add(apply);

        top.add(left);
        top.add(settings);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(800, 220));

        JSplitPane editors = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                wrap("Request", requestEditor.uiComponent()),
                wrap("Response", responseEditor.uiComponent()));
        editors.setResizeWeight(0.5);
        editors.setContinuousLayout(true);

        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editors);
        main.setResizeWeight(0.35);
        main.setContinuousLayout(true);

        add(top, BorderLayout.NORTH);
        add(main, BorderLayout.CENTER);

        for (BridgeLogEntry e : log.snapshot()) {
            model.add(e);
        }
        updateStatus();
        log.addListener(this);

        ui.applyThemeToComponent(this);
    }

    private void copyLlmInfo() {
        String text = LlmConnectionText.build(server.config(), server.boundPort());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        statusLabel.setText("Copied LLM connection info");
    }

    private void applySettings() {
        String host = hostField.getText() == null ? "" : hostField.getText().trim();
        if (wslListen.isSelected()) {
            host = BridgeConfig.WSL_BIND_HOST;
            hostField.setText(host);
        }
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(dialogParent, "Port must be a number 1-65535");
            return;
        }
        if (port <= 0 || port > 65535) {
            JOptionPane.showMessageDialog(dialogParent, "Port must be 1-65535");
            return;
        }
        String proxyHost = server.config().burpProxyHost();
        int proxyPort = server.config().burpProxyPort();
        String rawProxy = burpProxyField.getText() == null ? "" : burpProxyField.getText().trim();
        int colon = rawProxy.lastIndexOf(':');
        if (colon > 0) {
            proxyHost = rawProxy.substring(0, colon).trim();
            try {
                proxyPort = Integer.parseInt(rawProxy.substring(colon + 1).trim());
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(dialogParent, "Burp proxy must be host:port");
                return;
            }
        }
        BridgeConfig next =
                server.config().withBind(host, port).withSendViaProxy(sendViaProxy.isSelected(), proxyHost, proxyPort);
        try {
            next.save(api.persistence().preferences());
            server.restart(next);
            try {
                WslEndpoint.write(next, server.boundPort());
            } catch (Exception ignored) {
            }
            portField.setText(String.valueOf(server.boundPort()));
            statusLabel.setText("Listening on " + next.bindHost() + ":" + server.boundPort());
            api.logging()
                    .logToOutput(
                            "AI Bridge restarted on http://"
                                    + next.bindHost()
                                    + ":"
                                    + server.boundPort());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(dialogParent, "Could not bind " + host + ":" + port + " - " + e.getMessage());
        }
    }

    private static JPanel wrap(String title, java.awt.Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private void setColumnWidths() {
        int[] widths = {45, 95, 140, 70, 420, 60, 70, 80};
        for (int i = 0; i < widths.length && i < table.getColumnModel().getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
    }

    private void applyFilter() {
        String q = filterField.getText();
        if (q == null || q.isBlank()) {
            sorter.setRowFilter(null);
        } else {
            String needle = q.toLowerCase(Locale.ROOT);
            sorter.setRowFilter(new RowFilter<>() {
                @Override
                public boolean include(Entry<? extends HistoryTableModel, ? extends Integer> entry) {
                    BridgeLogEntry e = model.get(entry.getIdentifier());
                    if (e == null) {
                        return false;
                    }
                    return e.method().toLowerCase(Locale.ROOT).contains(needle)
                            || e.displayUrl().toLowerCase(Locale.ROOT).contains(needle)
                            || e.host().toLowerCase(Locale.ROOT).contains(needle)
                            || e.pathWithQuery().toLowerCase(Locale.ROOT).contains(needle)
                            || String.valueOf(e.status()).contains(needle)
                            || e.client().toLowerCase(Locale.ROOT).contains(needle)
                            || e.requestRaw().toLowerCase(Locale.ROOT).contains(needle)
                            || e.responseRaw().toLowerCase(Locale.ROOT).contains(needle);
                }
            });
        }
        updateStatus();
    }

    private void showSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            requestEditor.setRequest(HttpRequest.httpRequest());
            responseEditor.setResponse(HttpResponse.httpResponse());
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        BridgeLogEntry entry = model.get(modelRow);
        if (entry == null) {
            return;
        }
        try {
            HttpService svc;
            if (entry.targetHost() != null && !entry.targetHost().isBlank() && entry.targetPort() > 0) {
                svc = HttpService.httpService(entry.targetHost(), entry.targetPort(), entry.targetHttps());
            } else {
                svc = HttpService.httpService(server.config().bindHost(), server.boundPort(), false);
            }
            requestEditor.setRequest(HttpRequest.httpRequest(svc, entry.requestRaw()));
        } catch (Exception ex) {
            try {
                requestEditor.setRequest(HttpRequest.httpRequest(entry.requestRaw()));
            } catch (Exception ignored) {
            }
        }
        try {
            responseEditor.setResponse(HttpResponse.httpResponse(entry.responseRaw()));
        } catch (Exception ignored) {
        }
    }

    private void updateStatus() {
        int total = model.getRowCount();
        int shown = table.getRowCount();
        if (shown == total) {
            statusLabel.setText(total + " entries");
        } else {
            statusLabel.setText(shown + " / " + total + " entries");
        }
    }

    @Override
    public void onEntry(BridgeLogEntry entry) {
        SwingUtilities.invokeLater(() -> {
            model.add(entry);
            updateStatus();
            if (autoScroll.isSelected()) {
                int modelRow = 0;
                for (int i = 0; i < model.getRowCount(); i++) {
                    BridgeLogEntry e = model.get(i);
                    if (e != null && e.id() == entry.id()) {
                        modelRow = i;
                        break;
                    }
                }
                int view = table.convertRowIndexToView(modelRow);
                if (view >= 0) {
                    table.getSelectionModel().setSelectionInterval(view, view);
                    table.scrollRectToVisible(table.getCellRect(view, 0, true));
                }
            }
        });
    }

    @Override
    public void onCleared() {
        SwingUtilities.invokeLater(() -> {
            model.clear();
            try {
                requestEditor.setRequest(HttpRequest.httpRequest());
                responseEditor.setResponse(HttpResponse.httpResponse());
            } catch (Exception ignored) {
            }
            updateStatus();
        });
    }

    private static final class HistoryTableModel extends AbstractTableModel {
        // Proxy History style: host + method + URL + status
        private final String[] cols = {"#", "Time", "Host", "Method", "URL", "Status", "Length", "Time (ms)"};
        private final List<BridgeLogEntry> rows = new ArrayList<>();

        void add(BridgeLogEntry e) {
            rows.add(0, e);
            fireTableRowsInserted(0, 0);
        }

        void clear() {
            int n = rows.size();
            rows.clear();
            if (n > 0) {
                fireTableRowsDeleted(0, n - 1);
            }
        }

        BridgeLogEntry get(int row) {
            if (row < 0 || row >= rows.size()) {
                return null;
            }
            return rows.get(row);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int column) {
            return cols[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return switch (columnIndex) {
                case 0, 5, 6 -> Integer.class;
                case 7 -> Long.class;
                default -> String.class;
            };
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            BridgeLogEntry e = rows.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> (int) e.id();
                case 1 -> TIME_FMT.format(e.time());
                case 2 -> e.host();
                case 3 -> e.method();
                case 4 -> e.displayUrl();
                case 5 -> e.status();
                case 6 -> e.responseBodyLength();
                case 7 -> e.durationMs();
                default -> "";
            };
        }
    }
}
