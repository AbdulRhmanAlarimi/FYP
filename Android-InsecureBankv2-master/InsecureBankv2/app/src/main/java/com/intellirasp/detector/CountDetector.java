package com.intellirasp.detector;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * On-device count check (the "ZScore" half of Markov2+ZScore).
 * Counts what happens in the session (40 counters, the same as build_tabular() in
 * process_raw_files.py) and compares each counter with normal sessions from count_model.json:
 *     z = (count - mean) / spread
 * If the largest z is above "limit", the session has too much of something = alarm.
 * Counters only go up, so a counter that passes the limit mid-session stays above it.
 */
public class CountDetector {

    private static final String TAG = "IntelliRASP-COUNT";
    private static final String MODEL_FILE = "count_model.json";

    // Same lists as process_raw_files.py
    private static final Set<String> RULE_EVENTS =
            new HashSet<String>(Arrays.asList("ME-11", "ME-13", "ME-14", "ME-15", "ME-ML"));
    private static final Set<String> PRE_LOGIN_SCREENS = new HashSet<String>(Arrays.asList(
            "LoginActivity", "DoLogin", "SignUpActivity", "FilePrefActivity", "WrongLogin"));
    private static final String OWN_APP = "com.android.insecurebankv2";

    private static boolean loaded = false;
    private static String[] features;          // counter names, in the order of count_model.json
    private static double[] mean, spread;
    private static double limit;

    // State of the current session
    private static final Map<String, Double> counts = new HashMap<String, Double>();
    private static final Set<String> screens = new HashSet<String>();
    private static final Set<String> queryShapes = new HashSet<String>();
    private static final Set<String> endpoints = new HashSet<String>();
    private static boolean alarmed = false;
    private static double lastScore = 0;
    private static String lastFeature = "";

    /** Call once from RaspApp.onCreate(). */
    public static synchronized void init(Context context) {
        try {
            InputStream in = context.getAssets().open(MODEL_FILE);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) != -1) buf.write(b, 0, n);
            in.close();
            load(new JSONObject(buf.toString("UTF-8")));
            Log.i(TAG, "Count model loaded, " + features.length + " counters, limit " + limit);
        } catch (Exception e) {
            Log.e(TAG, "Could not load assets/" + MODEL_FILE, e);
        }
    }

    /** Read the model from its JSON (separate from init so the parity test can call it without Android). */
    public static synchronized void load(JSONObject model) throws org.json.JSONException {
        JSONArray f = model.getJSONArray("features");
        JSONArray m = model.getJSONArray("mean");
        JSONArray s = model.getJSONArray("spread");
        features = new String[f.length()];
        mean = new double[f.length()];
        spread = new double[f.length()];
        for (int i = 0; i < f.length(); i++) {
            features[i] = f.getString(i);
            mean[i] = m.getDouble(i);
            spread[i] = s.getDouble(i);
        }
        limit = model.getDouble("limit");
        reset();
        loaded = true;
    }

    private static void inc(String name) {
        Double v = counts.get(name);
        counts.put(name, v == null ? 1.0 : v + 1.0);
    }

    private static double get(String name) {
        Double v = counts.get(name);
        return v == null ? 0.0 : v;
    }

    /** Like a pandas column: a missing field is NaN, and NaN == "X" is false. */
    private static boolean is(JSONObject d, String key, String value) {
        return d.has(key) && !d.isNull(key) && value.equals(String.valueOf(d.opt(key)));
    }

    /** Update the counters with one event: the same rules as build_tabular(). */
    private static void count(String eventId, String component, JSONObject d) {
        inc("n_" + eventId);                                    // n_ME-01 ... n_ME-12
        inc("n_events");
        if (component != null) screens.add(component);          // n_screens = unique components

        if (is(d, "login_result", "FAILURE")) inc("n_login_failures");
        if (is(d, "sensitivity_classification", "SENSITIVE")) inc("n_sensitive_logs");
        if ("ME-06".equals(eventId) && is(d, "validation_result", "SUSPICIOUS")) inc("n_suspicious_input");

        if ("ME-10".equals(eventId)) {                           // network
            // a missing connection_result counts as an error, like str(NaN) = "nan" in Python
            String result = d.has("connection_result") && !d.isNull("connection_result")
                    ? String.valueOf(d.opt("connection_result")) : "nan";
            if (!result.startsWith("HTTP_2")) inc("n_http_errors");
            if (d.has("url_path") && !d.isNull("url_path")) {
                String path = String.valueOf(d.opt("url_path"));
                endpoints.add(path);
                inc("n_ep_" + path.replaceAll("^/+|/+$", ""));  // "/dotransfer" -> n_ep_dotransfer
            }
        }
        if ("ME-07".equals(eventId)) {                           // SQL
            if (is(d, "parameterization_status", "NOT_PARAMETERIZED")) inc("n_not_parameterized");
            if (d.has("query_structure") && !d.isNull("query_structure"))
                queryShapes.add(String.valueOf(d.opt("query_structure")));
        }
        if ("ME-09".equals(eventId) && is(d, "authentication_state", "ANONYMOUS")
                && !PRE_LOGIN_SCREENS.contains(component)) {
            inc("n_anon_privileged");                            // inside screen opened without login
        }
        if (("ME-09".equals(eventId) || "ME-12".equals(eventId)) && !"LoginActivity".equals(component)) {
            String caller = "UNKNOWN";                           // caller_package, else source_package, else UNKNOWN
            if (d.has("caller_package") && !d.isNull("caller_package")) caller = String.valueOf(d.opt("caller_package"));
            else if (d.has("source_package") && !d.isNull("source_package")) caller = String.valueOf(d.opt("source_package"));
            if (!"UNKNOWN".equals(caller) && !OWN_APP.equals(caller)) inc("n_external_caller");
        }
    }

    /** Value of one counter by its name in count_model.json. */
    private static double value(String name) {
        if ("n_screens".equals(name)) return screens.size();
        if ("n_query_shapes".equals(name)) return queryShapes.size();
        if ("n_endpoints".equals(name)) return endpoints.size();
        if ("n_failures".equals(name)) return get("n_login_failures") + get("n_http_errors");
        return get(name);
    }

    /** The largest z over all counters (and which counter it was). */
    public static synchronized double score() {
        double best = Double.NEGATIVE_INFINITY;
        for (int i = 0; i < features.length; i++) {
            double z = (value(features[i]) - mean[i]) / spread[i];
            if (z > best) { best = z; lastFeature = features[i]; }
        }
        return best;
    }

    /** Call for every RASP event (from Rasp.send). Returns true once, when a counter is too high. */
    public static synchronized boolean onEvent(String eventId, String component, JSONObject data) {
        if (!loaded || RULE_EVENTS.contains(eventId) || MarkovDetector.ruleOnly(eventId, component)) return false;
        count(eventId, component, data == null ? new JSONObject() : data);
        lastScore = score();
        Log.d(TAG, "max z " + String.format("%.2f", lastScore) + " (" + lastFeature + ")");
        if (!alarmed && lastScore > limit) {
            alarmed = true;
            Log.w(TAG, "ALARM: too many " + lastFeature + ", z " + lastScore + " > " + limit);
            return true;
        }
        return false;
    }

    public static synchronized double getLastScore() { return lastScore; }
    public static synchronized double getLimit() { return limit; }
    public static synchronized String getLastFeature() { return lastFeature; }

    /** Start a new session (e.g. on logout). */
    public static synchronized void reset() {
        counts.clear();
        screens.clear();
        queryShapes.clear();
        endpoints.clear();
        alarmed = false;
        lastScore = 0;
        lastFeature = "";
    }
}
