package com.intellirasp.detector;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * AS08 - SQL injection (rules in assets/rule_source/*.json - add a .json
 * file there to add a new command, no code)
 * Keeps its original IntelliRASP-AS08 log tag and logic.
 */
public class AS08SqlInjectionRule {

    private static final String TAG = "IntelliRASP-AS08";
    private static final String RULE_DIR = "rule_source";

    private static class Rule {
        String id, name, severity;
        Pattern pattern;
    }

    private static List<Rule> rules;

    private static synchronized List<Rule> loadRules(Context context) {
        if (rules != null) return rules;
        rules = new ArrayList<>();
        AssetManager am = context.getAssets();
        try {
            for (String file : am.list(RULE_DIR)) {
                if (!file.endsWith(".json")) continue;
                InputStream in = am.open(RULE_DIR + "/" + file);
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] b = new byte[4096];
                int n;
                while ((n = in.read(b)) != -1) buf.write(b, 0, n);
                in.close();
                JSONObject o = new JSONObject(buf.toString("UTF-8"));
                Rule r = new Rule();
                r.id = o.optString("id", file);
                r.name = o.optString("name", "");
                r.severity = o.optString("severity", "HIGH");
                r.pattern = Pattern.compile(o.getString("pattern"));
                rules.add(r);
                Log.i(TAG, "Loaded rule " + r.id + " (" + r.name + ")");
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to load rules from assets/" + RULE_DIR, e);
        }
        return rules;
    }

    /** true = injection attempt detected (a rule matched). */
    public static boolean check(Context context, String input) {
        if (input == null || input.isEmpty()) return false;
        for (Rule r : loadRules(context)) {
            if (r.pattern.matcher(input).find()) {
                Log.e(TAG, "ALERT: SQL injection attempt detected! rule=" + r.id
                        + " [" + r.severity + "] " + r.name);
                return true;
            }
        }
        Log.i(TAG, "No SQL injection pattern matched.");
        return false;
    }
}
