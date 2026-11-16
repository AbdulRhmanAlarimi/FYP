package com.intellirasp.detector;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * On-device Markov model (the same model as MarkovModel in ML/modeling/models.py).
 * Reads assets/markov_model.json, turns every RASP event into a "step" (token),
 * and adds up how surprising each step is after the previous one.
 * Average surprise above the threshold = unusual session = alarm.
 */
public class MarkovDetector {

    private static final String TAG = "IntelliRASP-ML";
    private static final String MODEL_FILE = "markov_model.json";

    // One single step this surprising = alarm at once, even before MIN_STEPS.
    //private static final double STEP_THRESHOLD = 5.21;

    // Do not raise an alarm before this many steps: the average is too noisy at the start
    private static final int MIN_STEPS = 3;
    // Same list as RULE_EVENTS in process_raw_files.py: these go to the rules, not to the model
    private static final Set<String> RULE_EVENTS =
            new HashSet<String>(Arrays.asList("ME-11", "ME-13", "ME-14", "ME-15"));

    private static boolean loaded = false;
    private static double threshold, unseenStep;
    private static JSONObject pairs, unseenAfter;

    // State of the current session
    private static String prev = "START";
    private static double total = 0;
    private static int steps = 0;
    private static boolean alarmed = false;

    /** Call once from RaspApp.onCreate(). */
    public static synchronized void init(Context context) {
        try {
            InputStream in = context.getAssets().open(MODEL_FILE);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) != -1) buf.write(b, 0, n);
            in.close();
            JSONObject model = new JSONObject(buf.toString("UTF-8"));
            threshold = model.getDouble("threshold");
            unseenStep = model.getDouble("unseen_step");
            unseenAfter = model.getJSONObject("unseen_after");
            pairs = model.getJSONObject("pairs");
            loaded = true;
            Log.i(TAG, "Model loaded, threshold " + threshold);
        } catch (Exception e) {
            Log.e(TAG, "Could not load assets/" + MODEL_FILE, e);
        }
    }

    /** Same as token() in process_raw_files.py. Both must give the exact same text. */
    static String token(String eventId, String component, JSONObject d) {
        StringBuilder t = new StringBuilder(eventId);
        if ("ME-09".equals(eventId)) {
            add(t, component);
            add(t, d.optString("authentication_state", null));
        } else if ("ME-10".equals(eventId)) {
            add(t, d.optString("url_path", null));
        } else if ("ME-07".equals(eventId)) {
            add(t, d.optString("operation", null));
            add(t, d.optString("parameterization_status", null));
        } else if ("ME-06".equals(eventId)) {
            add(t, d.optString("login_result", null));
        }
        return t.toString();
    }

    private static void add(StringBuilder t, String value) {
        if (value != null) t.append('|').append(value);   // missing field = left out, like pd.notna
    }

    /** Same as MarkovModel.surprise(a, b) in Python. */
    static double surprise(String a, String b) {
        JSONObject next = pairs.optJSONObject(a);
        if (next == null) return unseenStep;               // step a never seen in training
        if (next.has(b)) return next.optDouble(b);
        return unseenAfter.optDouble(a, unseenStep);       // b never seen after a
    }

    /**
     * Call for every RASP event (from Rasp.send). Returns true once, when the session becomes unusual.
     */
    public static synchronized boolean onEvent(String eventId, String component, JSONObject data) {
        if (!loaded || RULE_EVENTS.contains(eventId)) return false;
        String step = token(eventId, component, data == null ? new JSONObject() : data);
        total += surprise(prev, step);
        steps++;
        prev = step;

        double score = total / steps;
        Log.d(TAG, step + "  score " + String.format("%.3f", score));
        if (!alarmed && steps >= MIN_STEPS && score > threshold) {
            alarmed = true;
            Log.w(TAG, "ALARM: unusual session, score " + score + " > " + threshold + " at step " + step);
            return true;
        }
        return false;
    }

    /** Score of the whole session, exactly like MarkovModel.score() (adds the END step). For the parity test. */
    public static synchronized double finalScore() {
        return (total + surprise(prev, "END")) / (steps + 1);
    }

    /** Start a new session (e.g. on logout). */
    public static synchronized void reset() {
        prev = "START";
        total = 0;
        steps = 0;
        alarmed = false;
    }
}
