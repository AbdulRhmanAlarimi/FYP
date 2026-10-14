package com.android.insecurebankv2;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/*
 * ===========================================================================================
 *  IntelliRASP research hook - application event stream
 * ===========================================================================================
 *
 *  PURPOSE
 *  ------
 *  A single, dependency-free sink that every screen of the application reports to. Events
 *  are emitted twice:
 *
 *    1. logcat   ->  tag "InsecureRASP", one single-line JSON object per event.
 *                   `adb logcat -s InsecureRASP:I` gives the live behavioural stream.
 *
 *    2. a JSONL file inside the application private external files directory
 *                   /sdcard/Android/data/com.android.insecurebankv2/files/rasp_events.jsonl
 *                   `adb pull` of that file yields a ready-to-use behavioural dataset.
 *
 *  EVENT SCHEMA (stable - the ML pipeline keys off these names)
 *  ---------------------------------------------------------
 *    ts       ISO-8601 UTC timestamp, millisecond precision
 *    ts_ms    epoch millis (easier for feature extraction)
 *    seq      monotonically increasing counter, assigned on the calling thread
 *    session  UUID regenerated on every application start
 *    event    one of the EVENT_* constants below
 *    component  activity/component that produced the event
 *    user     the *username* only - never a password, token or session cookie
 *    result   "success" | "failure"
 *    op_id    correlates the requests of a single user action (e.g. the two calls made
 *             by one screen refresh)
 *    detail   optional, non-sensitive free text (max 220 chars, scrubbed)
 *
 *  DATA HANDLING
 *  -------------
 *  No password, no authentication token, no card number and no OTP is ever passed to this
 *  class. `registerSecret()` additionally installs the plaintext session password as a
 *  scrub string so that even an accidental copy/paste into a `detail` value is masked
 *  before the event leaves the process.
 *
 *  THIS CLASS IS NOT A VULNERABILITY. It is research instrumentation.
 * ===========================================================================================
 */
public final class RaspEvent {

    /* ------------------------------------------------------------------ logcat + file */
    public static final String TAG = "InsecureRASP";
    private static final String EVENT_FILE = "rasp_events.jsonl";
    private static final int DETAIL_MAX = 220;

    /* ------------------------------------------------------- application lifecycle */
    public static final String APP_START = "APP_START";
    public static final String APP_FOREGROUND = "APP_FOREGROUND";
    public static final String LOGOUT = "LOGOUT";
    public static final String SESSION_EXPIRED = "SESSION_EXPIRED";
    public static final String NAVIGATE = "NAVIGATE";

    /* ------------------------------------------------------------------ authentication */
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String LOGIN_FAILURE = "LOGIN_FAILURE";

    /* -------------------------------------------------------------------------- signup */
    public static final String SIGNUP_ATTEMPT = "SIGNUP_ATTEMPT";
    public static final String SIGNUP_SUCCESS = "SIGNUP_SUCCESS";
    public static final String SIGNUP_FAILURE = "SIGNUP_FAILURE";

    /* ------------------------------------------------------------- 1. account details */
    public static final String ACCOUNT_VIEW = "ACCOUNT_VIEW";
    public static final String ACCOUNT_REFRESH = "ACCOUNT_REFRESH";

    /* ---------------------------------------------------------- 2. transaction history */
    public static final String TRANSACTION_HISTORY_VIEW = "TRANSACTION_HISTORY_VIEW";
    public static final String TRANSACTION_SEARCH = "TRANSACTION_SEARCH";
    public static final String TRANSACTION_SEARCH_RESULT = "TRANSACTION_SEARCH_RESULT";

    /* ------------------------------------------------------------- 3. beneficiaries */
    public static final String BENEFICIARY_VIEW = "BENEFICIARY_VIEW";
    public static final String BENEFICIARY_ADD = "BENEFICIARY_ADD";
    public static final String BENEFICIARY_DELETE = "BENEFICIARY_DELETE";
    public static final String BENEFICIARY_SELECT = "BENEFICIARY_SELECT";

    /* -------------------------------------------------------------- 4. bill payment */
    public static final String BILL_PAYMENT = "BILL_PAYMENT";
    public static final String BILL_PAYMENT_HISTORY_VIEW = "BILL_PAYMENT_HISTORY_VIEW";

    /* ----------------------------------------------------------------- 5. profile */
    public static final String PROFILE_VIEW = "PROFILE_VIEW";
    public static final String PROFILE_UPDATE = "PROFILE_UPDATE";
    public static final String PASSWORD_CHANGE = "PASSWORD_CHANGE";

    /* ------------------------------------------------------------------ 6. deposit */
    public static final String DEPOSIT = "DEPOSIT";
    public static final String BALANCE_VIEW = "BALANCE_VIEW";

    /* ------------------------------------------------------------------ pre-existing */
    public static final String TRANSFER = "TRANSFER";
    public static final String STATEMENT_VIEW = "STATEMENT_VIEW";

    /* ----------------------------------------------------------------------- generic */
    public static final String SERVER_REQUEST = "SERVER_REQUEST";
    public static final String SERVER_RESPONSE = "SERVER_RESPONSE";
    public static final String CLIENT_ERROR = "CLIENT_ERROR";

    public static final String RESULT_SUCCESS = "success";
    public static final String RESULT_FAILURE = "failure";

    /* ------------------------------------------------------------------------ internals */
    private static Context appContext;
    private static final AtomicInteger SEQ = new AtomicInteger(0);
    private static final AtomicLong OP_COUNTER = new AtomicLong(0);
    private static volatile String sessionId = UUID.randomUUID().toString();
    private static volatile String scrubSecret = null;
    private static final ExecutorService WRITER =
            Executors.newSingleThreadExecutor(new java.util.concurrent.ThreadFactory() {
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "rasp-event-writer");
                    t.setDaemon(true);
                    return t;
                }
            });

    private static final SimpleDateFormat ISO =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);

    static {
        ISO.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    private RaspEvent() {
    }

    /* ============================================================================ setup */

    /**
     * Called once from LoginActivity.onCreate(). Safe to call repeatedly.
     */
    public static synchronized void init(Context context) {
        appContext = context.getApplicationContext();
        String incoming = ISO.format(new Date());
        log(APP_START, "Application", "anonymous", RESULT_SUCCESS,
                newOpId(), "pid=" + android.os.Process.myPid() + " ts_local=" + incoming);
    }

    /**
     * Starts a new logical session (called on every successful LOGIN so that sequences can
     * be split on authentication boundaries).
     */
    public static String newSession() {
        sessionId = UUID.randomUUID().toString();
        return sessionId;
    }

    public static String session() {
        return sessionId;
    }

    /**
     * Installs a value that must never appear in an event body. Used for the plaintext
     * session password. Passing null clears it.
     */
    public static void registerSecret(String secret) {
        scrubSecret = (secret == null || secret.length() < 3) ? null : secret;
    }

    /**
     * @return a short correlation id shared by every network round trip of one screen.
     */
    public static String newOpId() {
        return "op" + OP_COUNTER.incrementAndGet();
    }

    public static int eventCount() {
        return SEQ.get();
    }

    /* =========================================================================== emit */

    public static void log(String event, String component, String user, String result,
                           String opId, String detail) {
        String line;
        try {
            JSONObject o = new JSONObject();
            o.put("ts", ISO.format(new Date()));
            o.put("ts_ms", System.currentTimeMillis());
            o.put("seq", SEQ.incrementAndGet());
            o.put("session", sessionId);
            o.put("event", event);
            o.put("component", component == null ? "unknown" : component);
            o.put("user", (user == null || user.length() == 0) ? "anonymous" : user);
            o.put("result", result == null ? RESULT_SUCCESS : result);
            o.put("op_id", opId == null ? "-" : opId);
            if (detail != null && detail.length() > 0) {
                o.put("detail", scrub(detail));
            }
            line = o.toString();
        } catch (Exception e) {
            // Never let telemetry break the application.
            line = "{\"event\":\"" + event + "\",\"error\":\"json\"}";
        }
        Log.i(TAG, line);
        writeAsync(line);
    }

    public static void log(String event, String component, String user, String result,
                           String opId) {
        log(event, component, user, result, opId, null);
    }

    public static void ok(String event, String component, String user, String opId, String detail) {
        log(event, component, user, RESULT_SUCCESS, opId, detail);
    }

    public static void fail(String event, String component, String user, String opId, String detail) {
        log(event, component, user, RESULT_FAILURE, opId, detail);
    }

    public static void error(String component, String user, String opId, String detail) {
        log(CLIENT_ERROR, component, user, RESULT_FAILURE, opId, detail);
    }

    /* ======================================================================== helpers */

    /**
     * Removes the registered plaintext secret and clamps the length. This is a
     * defence-in-depth measure for the *benign* instrumentation path, not a control.
     */
    private static String scrub(String detail) {
        String s = detail;
        String secret = scrubSecret;
        if (secret != null && s.contains(secret)) {
            s = s.replace(secret, "***");
        }
        s = s.replace('\n', ' ').replace('\r', ' ');
        if (s.length() > DETAIL_MAX) {
            s = s.substring(0, DETAIL_MAX) + "...";
        }
        return s;
    }

    private static void writeAsync(final String line) {
        final Context ctx = appContext;
        if (ctx == null) {
            return;
        }
        WRITER.execute(new Runnable() {
            @Override
            public void run() {
                appendLine(ctx, line);
            }
        });
    }

    private static void appendLine(Context ctx, String line) {
        OutputStreamWriter w = null;
        try {
            File f = eventFile(ctx);
            if (f == null) {
                return;
            }
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            w = new OutputStreamWriter(new FileOutputStream(f, true), "UTF-8");
            w.write(line);
            w.write("\n");
            w.flush();
        } catch (IOException e) {
            // dataset persistence is best effort
        } catch (Exception e) {
            // dataset persistence is best effort
        } finally {
            if (w != null) {
                try {
                    w.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Public so a researcher can read the trail back from inside the application
     * (used by the self-check screen and by `adb` tooling).
     */
    public static File eventFile(Context context) {
        Context c = context == null ? appContext : context;
        if (c == null) {
            return null;
        }
        File dir = c.getExternalFilesDir(null);
        if (dir == null) {
            dir = c.getFilesDir();
        }
        return dir == null ? null : new File(dir, EVENT_FILE);
    }

    /**
     * @return absolute path of the JSONL event trail, or null when nothing is writable yet.
     */
    public static String eventFilePath(Context context) {
        File f = eventFile(context);
        return f == null ? null : f.getAbsolutePath();
    }
}
