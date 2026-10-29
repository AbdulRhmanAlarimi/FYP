import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Debug;
import android.util.Log;

public class AS07DebuggerRule {

    private static final String TAG = "IntelliRASP-AS07";

    public static void check(Context context) {

        if (Debug.isDebuggerConnected()) {
            Log.e(TAG, "ALERT: A Debugger is attached!");
            //we need to exit the app and send the alert to the SIEM or grafana المهم نرسل الاليرت و نقفل البرنامج عن اليوسر
		
        } else if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            Log.w(TAG, "WARNING: Application is debuggable!");
            // we need to send an alert to the SIEM only no need to terminate هنا التطبيق قابل ان يصير له ديبوج لكن اليوزر م مسوي له ديبوج

        } else {
            Log.i(TAG, "No debugger attached; application is not debuggable.");
            
        }
    }
}
