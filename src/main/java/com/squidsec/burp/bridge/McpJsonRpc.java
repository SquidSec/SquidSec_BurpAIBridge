package com.squidsec.burp.bridge;

import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

/** MCP JSON-RPC 2.0 over HTTP (initialize, tools/list, tools/call, ping). */
public final class McpJsonRpc {

    private McpJsonRpc() {}

    public static Map<String, Object> handle(
            Map<String, Object> msg, boolean authorized, BiFunction<String, Map<String, Object>, Object> caller) {
        Object id = msg.get("id");
        String method = Json.str(msg, "method");
        Map<String, Object> params = params(msg.get("params"));

        if ("initialize".equals(method)) {
            return ok(id, McpCatalog.initializeResult(Json.str(params, "protocolVersion")));
        }
        if ("notifications/initialized".equals(method) || "initialized".equals(method)) {
            return null;
        }
        if ("ping".equals(method)) {
            return ok(id, Json.obj());
        }
        if ("tools/list".equals(method)) {
            Map<String, Object> result = Json.obj();
            result.put("tools", McpCatalog.tools());
            return ok(id, result);
        }
        if ("tools/call".equals(method)) {
            if (!authorized) {
                return err(id, -32001, "unauthorized");
            }
            String name = Json.str(params, "name");
            Map<String, Object> args = params(params.get("arguments"));
            try {
                Object payload = caller.apply(name, args);
                return ok(id, toolResult(payload, isError(payload)));
            } catch (Exception e) {
                return ok(id, toolResult(e.getMessage() == null ? "error" : e.getMessage(), true));
            }
        }
        if (id != null) {
            return err(id, -32601, "Method not found: " + method);
        }
        return null;
    }

    public static Map<String, Object> toolResult(Object payload, boolean isError) {
        String text = payload instanceof String s ? s : Json.stringify(payload);
        Map<String, Object> part = Json.obj();
        part.put("type", "text");
        part.put("text", text);
        List<Object> content = Json.arr();
        content.add(part);
        Map<String, Object> result = Json.obj();
        result.put("content", content);
        result.put("isError", isError);
        return result;
    }

    static boolean isError(Object payload) {
        if (payload instanceof Map<?, ?> m) {
            return m.containsKey("error");
        }
        return false;
    }

    static Map<String, Object> ok(Object id, Object result) {
        Map<String, Object> m = Json.obj();
        m.put("jsonrpc", "2.0");
        m.put("id", id);
        m.put("result", result);
        return m;
    }

    static Map<String, Object> err(Object id, int code, String message) {
        Map<String, Object> error = Json.obj();
        error.put("code", code);
        error.put("message", message);
        Map<String, Object> m = Json.obj();
        m.put("jsonrpc", "2.0");
        m.put("id", id);
        m.put("error", error);
        return m;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> params(Object o) {
        if (o instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        return Json.obj();
    }
}
