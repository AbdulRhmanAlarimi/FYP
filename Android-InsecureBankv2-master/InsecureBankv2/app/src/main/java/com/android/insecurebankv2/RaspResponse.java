package com.android.insecurebankv2;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * The one place that decides WHAT HAPPENS after a detection (rules or ML).
 * Order is always: 1. save the alert on the phone, 2. do the action.
 * Saving comes first because "terminate" kills the app and nothing after it runs.
 *
 * Actions (same levels as rules.py):  log < alert < block < terminate
 *   log       = only saved
 *   alert     = saved only, silent (the attacker does not know; the SIEM gets the detection event)
 *   block     = saved + generic message + logout (back to the login screen)
 *   terminate = saved + generic message + close the app
 * Messages never say WHAT was detected, so they do not help an attacker.
 */
public class RaspResponse {

    private static final String TAG = "IntelliRASP-ACTION";
    private static final String ALERT_FILE = "alerts.jsonl";   // in the app's private storage
    private static final long TERMINATE_DELAY_MS = 1500;      // time to show the message and finish sending

    private static Context app;
    private static final Handler main = new Handler(Looper.getMainLooper());

    /** Call once from RaspApp.onCreate(). */
    public static void init(Context context) {
        app = context.getApplicationContext();
    }

    /**
     * @param action  "log" | "alert" | "block" | "terminate"
     * @param source  "RULE" or "ML"
     * @param ruleId  e.g. "AS07", "AS08", "Markov2", "Count"
     * @param reason  short text, never passwords or the attacker's input
     */
    public static void respond(String action, String source, String ruleId, String reason) {
        if (app == null) return;
        save(action, source, ruleId, reason);            // 1. save first
        Log.w(TAG, action.toUpperCase(Locale.US) + " [" + source + "/" + ruleId + "] " + reason);

        if ("block".equals(action)) {                    // 2. then act (messages never say WHAT was detected)
            toast("Your session too long ended. Please log in again.");
            logout();
        } else if ("terminate".equals(action)) {
            toast("This app cannot continue for security reasons.");
            terminate();
        }
        // "log" and "alert": silent, saved only (alert also reaches the SIEM through the detection event)
    }

    /** One JSON line per alert in /data/data/com.android.insecurebankv2/files/alerts.jsonl */
    private static synchronized void save(String action, String source, String ruleId, String reason) {
        FileOutputStream out = null;
        try {
            JSONObject a = new JSONObject();
            a.put("time", now());
            a.put("action", action);
            a.put("source", source);
            a.put("rule", ruleId);
            a.put("reason", reason);
            out = app.openFileOutput(ALERT_FILE, Context.MODE_PRIVATE | Context.MODE_APPEND);
            out.write((a.toString() + "\n").getBytes("UTF-8"));
        } catch (Exception e) {
            Log.e(TAG, "Could not save alert", e);
        } finally {
            try { if (out != null) out.close(); } catch (Exception ignored) {}
        }
    }

    /** Toasts must run on the main (UI) thread; detections can come from any thread. */
    private static void toast(final String text) {
        main.post(new Runnable() {
            @Override public void run() {
                Toast.makeText(app, text, Toast.LENGTH_LONG).show();
            }
        });
    }

    /** Same as BankActivity.performLogout(), plus a fresh session for the detectors. */
    private static void logout() {
        main.post(new Runnable() {
            @Override public void run() {
                BankSession.clear(app);
                RaspApp.loggedIn = false;
                com.intellirasp.detector.MarkovDetector.reset();   // the next session starts from START
                com.intellirasp.detector.CountDetector.reset();
                Intent i = new Intent(app, LoginActivity.class);
                // NEW_TASK: we start from the Application, not from a screen
                // CLEAR_TASK: remove every open screen, so "back" cannot return to them
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                app.startActivity(i);
            }
        });
    }

    /** Close the app after a short delay, so the message shows and the SIEM alert gets sent. */
    private static void terminate() {
        main.postDelayed(new Runnable() {
            @Override public void run() {
                android.os.Process.killProcess(android.os.Process.myPid());
                System.exit(0);
            }
        }, TERMINATE_DELAY_MS);
    }

    private static String now() {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date());
    }
}
