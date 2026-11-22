package com.intellirasp.detector;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * On-device Markov model (the same model as MarkovModel in ML/modeling/models.py).
 * Reads assets/markov_model.json, turns every RASP event into a "step" (token),
 * and adds up how surprising each step is after the previous step(s).
 * order 1 = looks at the previous step, order 2 = at the previous two steps ("A > B").
 * Average surprise above the threshold = unusual session = alarm.
 */
public class MarkovDetector {

    private static final String TAG = "IntelliRASP-ML";
    private static final String MODEL_FILE = "markov_model.json";

    // Used only when the JSON has no "prefix_thresholds": no alarm before this many steps
    private static final int MIN_STEPS = 5;
    // Same list as RULE_EVENTS in process_raw_files.py: these go to the rules, not to the model.
    // ME-ML is the alert event we post ourselves: never feed it back into scoring.
    private static final Set<String> RULE_EVENTS =
            new HashSet<String>(Arrays.asList("ME-11", "ME-13", "ME-14", "ME-15", "ME-ML"));

    private static boolean loaded = false;
    private static int order = 1;
    private static double threshold, unseenStep;
    private static double[] prefixThresholds;      // threshold after 1, 2, 3 ... steps (null = not in the JSON)
    private static JSONObject pairs, unseenAfter;

    // State of the current session
    private static final LinkedList<String> history = new LinkedList<String>();   // the last `order` steps
    private static double total = 0;
    private static int steps = 0;
    private static boolean alarmed = false;
    private static double lastScore = 0;
    private static String lastStep = "";

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
            Log.i(TAG, "Model loaded, order " + order + ", threshold " + threshold
                    + (prefixThresholds != null ? ", " + prefixThresholds.length + " prefix thresholds" : ""));
        } catch (Exception e) {
            Log.e(TAG, "Could not load assets/" + MODEL_FILE, e);
        }
    }

    /** Read the model from its JSON (separate from init so the parity test can call it without Android). */
    public static synchronized void load(JSONObject model) throws org.json.JSONException {
        order = model.optInt("order", 1);              // old files have no "order" = order 1
        threshold = model.getDouble("threshold");
        unseenStep = model.getDouble("unseen_step");
        unseenAfter = model.getJSONObject("unseen_after");
        pairs = model.getJSONObject("pairs");
        JSONArray pt = model.optJSONArray("prefix_thresholds");
        prefixThresholds = null;
        if (pt != null && pt.length() > 0) {
            prefixThresholds = new double[pt.length()];
            for (int i = 0; i < pt.length(); i++) prefixThresholds[i] = pt.getDouble(i);
        }
        reset();
        loaded = true;
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

    /** Same as rule_only in process_raw_files.load_events(): AS08's search check and its cache writes are for the rules only. */
    static boolean ruleOnly(String eventId, String component) {
        return "TransactionCacheDb".equals(component) && ("ME-07".equals(eventId) || "ME-02".equals(eventId));
    }

    /** The context = the last `order` steps joined with " > ", like MarkovModel.pairs() in Python. */
    private static String context() {
        StringBuilder c = new StringBuilder();
        for (String s : history) {
            if (c.length() > 0) c.append(" > ");
            c.append(s);
        }
        return c.toString();
    }

    /** Same as MarkovModel.surprise(a, b) in Python. a = the context ("A > B" for order 2). */
    static double surprise(String a, String b) {
        JSONObject next = pairs.optJSONObject(a);
        if (next == null) return unseenStep;               // context a never seen in training
        if (next.has(b)) return next.optDouble(b);
        return unseenAfter.optDouble(a, unseenStep);       // b never seen after a
    }

    /** The limit for the current number of steps. */
    private static double currentThreshold() {
        if (prefixThresholds == null) return threshold;
        int k = Math.max(1, Math.min(steps, prefixThresholds.length));
        return prefixThresholds[k - 1];
    }

    /** Call for every RASP event (from Rasp.send). Returns true once, when the session becomes unusual. */
    public static synchronized boolean onEvent(String eventId, String component, JSONObject data) {
        if (!loaded || RULE_EVENTS.contains(eventId) || ruleOnly(eventId, component)) return false;
        String step = token(eventId, component, data == null ? new JSONObject() : data);
        total += surprise(context(), step);
        steps++;
        history.addLast(step);                          // slide the window: drop the oldest step
        history.removeFirst();

        double score = total / steps;
        double limit = currentThreshold();
        lastScore = score;
        lastStep = step;
        Log.d(TAG, step + "  score " + String.format("%.3f", score) + "  limit " + String.format("%.3f", limit));

        boolean enoughSteps = prefixThresholds != null || steps >= MIN_STEPS;
        if (!alarmed && enoughSteps && score > limit) {
            alarmed = true;
            Log.w(TAG, "ALARM: unusual session, score " + score + " > " + limit + " at step " + step);
            return true;
        }
        return false;
    }

    /** Last running average score (for the ME-ML alert payload). */
    public static synchronized double getLastScore() { return lastScore; }

    /** The limit that was used for the last step (for the ME-ML alert payload). */
    public static synchronized double getThreshold() { return loaded ? currentThreshold() : threshold; }

    /** Token that triggered the latest score update. */
    public static synchronized String getLastStep() { return lastStep; }

    /** Score of the whole session, exactly like MarkovModel.score() (adds the END step). For the parity test. */
    public static synchronized double finalScore() {
        return (total + surprise(context(), "END")) / (steps + 1);
    }

    /** Start a new session (e.g. on logout). */
    public static synchronized void reset() {
        history.clear();
        for (int i = 0; i < order; i++) history.add("START");   // order 2: "START > START"
        total = 0;
        steps = 0;
        alarmed = false;
        lastScore = 0;
        lastStep = "";
    }
}
