package com.android.insecurebankv2;

import android.util.Log;
import org.json.JSONObject;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date; //Date 
import java.util.Locale;
import java.util.TimeZone;

//OS & Emulator
import android.os.Build;
import android.os.Debug;
import java.io.File;


public class Rasp {
    // 10.0.2.2 = your PC, seen from the emulator
    private static final String SERVER = "http://10.0.2.2:8000/events";

    //Data that for json 
    public static void send(
        final String eventId,
        final String eventType,
        final String component,
        final JSONObject data
    )
    {
        new Thread(new Runnable(){ // network is not allowed on main thread
            @Override 
            public void run(){
                try{
                    JSONObject event =  new JSONObject();
                    event.put("event_id",eventId);
                     event.put("event_type", eventType);
                    event.put("timestamp", now());
                    event.put("component", component);
                    event.put("data", data);

                    // connection with server let in lesn
                    HttpURLConnection conn = (HttpURLConnection) new URL(SERVER).openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(3000);

                    OutputStream out = conn.getOutputStream();
                    out.write(event.toString().getBytes("UTF-8"));
                    out.close();

                    Log.i("RASP", "sent " + eventType + " -> HTTP " + conn.getResponseCode());
                    conn.disconnect();
                }
                //Catch
                catch (Exception e){
                    Log.e("RASP", "send failed "+ e);
                }
            }
        }).start();
    }


    // For SharedPreferences hook => ME-01
    public static void prefs(String fileName, String key, String operation,
                         boolean ok, String component) {
    try {
        JSONObject d = new JSONObject();
        d.put("preference_file_name", fileName);
        d.put("key", key);                 // the key name only, never the value
        d.put("operation", operation);     // READ, WRITE or DELETE
        d.put("status", ok ? "SUCCESS" : "FAILURE");
        send("ME-01", "SHARED_PREFERENCES_ACCESS", component, d);
    } catch (org.json.JSONException e) {
        e.printStackTrace();
    }
}

    // "ME-05", "APPLICATION_LOG_EVENT"
    public static void log(String level, String tag, String message, String component) {
        try {
            boolean sensitive = message.toLowerCase()
                    .matches(".*(password|passwd|account=|token|pin).*");
            JSONObject d = new JSONObject();
            d.put("log_level", level);
            d.put("tag", tag);
            d.put("message_length", message.length());   // never the message itself
            d.put("sensitivity_classification", sensitive ? "SENSITIVE" : "NORMAL");
            send("ME-05", "APPLICATION_LOG_EVENT", component, d);
        } catch (org.json.JSONException e) {
            e.printStackTrace();
        }
    }

    // hook "ME-10", "NETWORK_CONNECTION"
    public static void network(String host, String port, String protocol, String method,
                           String path, int statusCode, long bytesReceived, String component) {
        try {
            JSONObject d = new JSONObject();
            d.put("destination_domain", host);
            d.put("destination_ip", host);
            d.put("destination_port", port);
            d.put("protocol", protocol);          // "http" here is a red flag
            d.put("http_method", method);
            d.put("url_path", path);
            d.put("calling_component", component);
            d.put("connection_result", "HTTP_" + statusCode);
            d.put("bytes_sent", -1);              // unknown with this old HttpClient
            d.put("bytes_received", bytesReceived);
            send("ME-10", "NETWORK_CONNECTION", component, d);
        } catch (org.json.JSONException e) {
            e.printStackTrace();
        }
    }

    private static boolean envStarted = false;

    public static synchronized void startEnvChecks() {
        if (envStarted) return;          // only once per app run
        envStarted = true;
        new Thread(new Runnable() {
            @Override
            public void run() {
                rootCheck();
                emulatorCheck();
                Boolean last = null;
                while (true) {           // send only when the debugger state changes
                    boolean attached = Debug.isDebuggerConnected();
                    if (last == null || attached != last) {
                        debuggerEvent(attached);
                        last = attached;
                    }
                    try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
                }
            }
        }).start();
    }

    private static void debuggerEvent(boolean attached) {
        try {
            JSONObject d = new JSONObject();
            d.put("debugger_state", attached ? "ATTACHED" : "DETACHED");
            d.put("process_id", android.os.Process.myPid());
            d.put("detection_result", attached ? "DETECTED" : "NOT_DETECTED");
            send("ME-11", "DEBUGGER_ATTACHMENT", "Rasp", d);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }

    private static void rootCheck() {
        try {
            String[] paths = {"/system/bin/su", "/system/xbin/su", "/sbin/su",
                            "/system/app/Superuser.apk", "/data/local/xbin/su"};
            StringBuilder found = new StringBuilder();
            for (String p : paths) if (new File(p).exists()) found.append(p).append(",");
            boolean testKeys = Build.TAGS != null && Build.TAGS.contains("test-keys");
            boolean rooted = found.length() > 0 || testKeys;
            JSONObject d = new JSONObject();
            d.put("root_indicator_type", found.length() > 0 ? "SU_BINARY" : testKeys ? "TEST_KEYS" : "NONE");
            d.put("privileged_state_indicator", testKeys);
            d.put("suspicious_artifact_indicator", found.toString());
            d.put("detection_result", rooted ? "DETECTED" : "NOT_DETECTED");
            send("ME-14", "ROOT_ENVIRONMENT", "Rasp", d);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }

    private static void emulatorCheck() {
        try {
            StringBuilder hits = new StringBuilder();
            if (Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.contains("emulator")) hits.append("FINGERPRINT,");
            if (Build.HARDWARE.equals("goldfish") || Build.HARDWARE.equals("ranchu")) hits.append("HARDWARE,");
            if (Build.MODEL.contains("sdk") || Build.MODEL.contains("Emulator")) hits.append("MODEL,");
            if (Build.PRODUCT.contains("sdk")) hits.append("PRODUCT,");
            JSONObject d = new JSONObject();
            d.put("emulator_indicator_type", hits.length() > 0 ? hits.toString() : "NONE");
            d.put("device_system_properties", "model=" + Build.MODEL + ";product=" + Build.PRODUCT);
            d.put("hardware_indicators", Build.HARDWARE);
            d.put("detection_result", hits.length() > 0 ? "DETECTED" : "NOT_DETECTED");
            send("ME-15", "EMULATOR_ENVIRONMENT_DETECTION", "Rasp", d);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }


    // ME-07 + ME-02: one call sends both events
    public static void sql(String dbName, String operation, String table, String selection,
                        String[] args, boolean ok, String component) {
        try {
            String where = selection == null ? "" : selection;
            // replace values with ? so normal queries always have the same "shape"
            String structure = operation + " " + table + (where.isEmpty() ? "" : " WHERE "
                    + where.replaceAll("'[^']*'", "'?'").replaceAll("\\b\\d+\\b", "N"));
            int count = args == null ? 0 : args.length;
            String result = ok ? "SUCCESS" : "ERROR";

            JSONObject q = new JSONObject();
            q.put("query_structure", structure);
            q.put("operation", operation);
            q.put("target_table", table);
            q.put("parameterization_status", where.isEmpty() || where.contains("?") ? "PARAMETERIZED" : "NOT_PARAMETERIZED");
            q.put("parameter_count", count);
            q.put("parameter_types", "STRING");
            q.put("execution_result", result);
            send("ME-07", "SQL_QUERY_EXECUTION", component, q);

            JSONObject a = new JSONObject();
            a.put("database_name", dbName);
            a.put("table_name", table);
            a.put("operation", operation);
            a.put("parameter_count", count);
            a.put("parameter_types", "STRING");
            a.put("status", result);
            send("ME-02", "SQLITE_DB_ACCESS", component, a);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }

    // ME-09 for the content provider: who is calling it?
    public static void provider(String name, String operation, int callerUid, String callerPackage) {
        try {
            JSONObject d = new JSONObject();
            d.put("component_type", "PROVIDER");
            d.put("component_name", name);
            d.put("caller_uid", callerUid);
            d.put("caller_package", callerPackage == null ? "UNKNOWN" : callerPackage);
            d.put("intent_action", operation);
            d.put("intent_data", "content");
            d.put("exported_status", true);
            d.put("authentication_state", RaspApp.loggedIn ? "AUTHENTICATED" : "ANONYMOUS");
            d.put("invocation_result", "ALLOWED");
            send("ME-09", "ANDROID_COMPONENT_INVOCATION", "TrackUserContentProvider", d);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }

    // ME-03: file read/write
    public static void file(String path, String operation, boolean ok, String component) {
        try {
            java.io.File f = new java.io.File(path);
            String storage = path.contains("/Android/data/") || path.startsWith("/data/") ? "INTERNAL" : "EXTERNAL";
            String name = f.getName();
            JSONObject d = new JSONObject();
            d.put("file_path", path);
            d.put("file_type", name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : "none");
            d.put("storage_type", storage);
            d.put("operation", operation);
            d.put("file_size", f.exists() ? f.length() : 0);
            d.put("status", ok ? "SUCCESS" : "FAILURE");
            send("ME-03", "FILE_ACCESS", component, d);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }

    // ME-08: every page the WebView loads
    public static void webview(String url, String source, boolean jsEnabled, String component) {
        try {
            android.net.Uri u = android.net.Uri.parse(url);
            int params = 0;
            try { params = u.getQueryParameterNames().size(); } catch (Exception ignored) {}
            JSONObject d = new JSONObject();
            d.put("url", url);
            d.put("num_of_params", params);
            d.put("scheme", u.getScheme());
            d.put("domain", u.getHost() == null ? "" : u.getHost());
            d.put("path", u.getPath());
            d.put("navigation_source", source);
            d.put("javascript_execution_status", jsEnabled ? "ENABLED" : "DISABLED");
            send("ME-08", "WEBVIEW_ACTIVITY", component, d);
        } catch (org.json.JSONException e) { e.printStackTrace(); }
    }

    private static String now(){
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }
}
