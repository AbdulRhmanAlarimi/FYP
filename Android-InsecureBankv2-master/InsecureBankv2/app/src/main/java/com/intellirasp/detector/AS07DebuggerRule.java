package com.intellirasp.detector;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;
import android.util.Log;

public class AS07DebuggerRule {

    private static final String TAG = "IntelliRASP-AS07";

    public static boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected();
    }

    public static boolean isDebuggable(Context context) {
        return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    /** true = a debugger is attached (a rule matched). */
    public static boolean check(Context context) {
        boolean attached = isDebuggerAttached();

        if (attached) {
            Log.e(TAG, "ALERT: A Debugger is attached!");
            //we need to exit the app and send the alert to the SIEM or grafana المهم نرسل الاليرت و نقفل البرنامج عن اليوسر

        } else if (isDebuggable(context)) {
            Log.w(TAG, "WARNING: Application is debuggable!");
            // we need to send an alert to the SIEM only no need to terminate هنا التطبيق قابل ان يصير له ديبوج لكن اليوزر م مسوي له ديبوج

        } else {
            Log.i(TAG, "No debugger attached; application is not debuggable.");

        }

        return attached;
    }

    // v2 rule: stricter runtime-debug risk (attached debugger OR debuggable build).
    public static boolean isDebuggerAttached_v2() {
        return isDebuggerAttached();
    }

    public static boolean isDebuggable_v2(Context context) {
        return isDebuggable(context);
    }

    public static boolean check_v2(Context context) {
        boolean attached = isDebuggerAttached();
        boolean debuggable = isDebuggable(context);
        if (attached || debuggable) {
            Log.e(TAG, "ALERT_v2: debugger/runtime debug risk attached=" + attached
                    + " debuggable=" + debuggable);
            return true;
        }
        Log.i(TAG, "check_v2: no debugger risk detected.");
        return false;
    }
}
