package com.android.insecurebankv2;

import android.app.Activity;
import android.app.Application;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import org.json.JSONObject;
import java.security.MessageDigest;

public class RaspApp extends Application {
    // After the first run, paste your integrity_value here (step 4)
    private static final String EXPECTED_CERT_SHA256 = "b8fb634add85da8d849acc19380819ca8ae2bc7ee10726f572db4ac452f66c18";
    public static boolean loggedIn = false;

    @Override
    public void onCreate() {
        super.onCreate();
        Rasp.startEnvChecks();
        integrityCheck();
        watchClipboard();
        registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity a, Bundle b) { onScreenOpened(a); }
            @Override public void onActivityStarted(Activity a) {}
            @Override public void onActivityResumed(Activity a) {}
            @Override public void onActivityPaused(Activity a) {}
            @Override public void onActivityStopped(Activity a) {}
            @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
            @Override public void onActivityDestroyed(Activity a) {}
        });
    }

    // ME-09 for every screen, ME-12 when a screen is opened with a link
    private void onScreenOpened(Activity a) {
        try {
            Intent intent = a.getIntent();
            boolean exported = getPackageManager().getActivityInfo(a.getComponentName(), 0).exported;
            String caller = "UNKNOWN";
            if (Build.VERSION.SDK_INT >= 22 && a.getReferrer() != null) caller = a.getReferrer().getHost();
            String screen = a.getClass().getSimpleName();
            String auth = loggedIn ? "AUTHENTICATED" : "ANONYMOUS";

            JSONObject d = new JSONObject();
            d.put("component_type", "ACTIVITY");
            d.put("component_name", a.getClass().getName());
            d.put("caller_uid", "UNKNOWN");
            d.put("caller_package", caller);
            d.put("intent_action", intent != null ? intent.getAction() : "NONE");
            d.put("intent_data", intent != null && intent.getData() != null ? intent.getData().getScheme() : "NONE");
            d.put("exported_status", exported);
            d.put("authentication_state", auth);
            d.put("invocation_result", "ALLOWED");
            Rasp.send("ME-09", "ANDROID_COMPONENT_INVOCATION", screen, d);

            Uri uri = intent != null ? intent.getData() : null;
            if (uri != null && Intent.ACTION_VIEW.equals(intent.getAction())) {
                JSONObject l = new JSONObject();
                l.put("uri_scheme", uri.getScheme());
                l.put("host", uri.getHost());
                l.put("path", uri.getPath());
                l.put("parameter_metadata", "count=" + uri.getQueryParameterNames().size());
                l.put("source_package", caller);
                l.put("source_uid", "UNKNOWN");
                l.put("destination_component", a.getClass().getName());
                l.put("authentication_state", auth);
                l.put("authorization_result", "ALLOWED");
                Rasp.send("ME-12", "DEEP_LINK_INVOCATION", screen, l);
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    // ME-13: is this APK signed with OUR key? A patched APK has a different key
    private void integrityCheck() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(info.signatures[0].toByteArray());
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            JSONObject d = new JSONObject();
            d.put("application_identity", getString(R.string.app_name));
            d.put("package_name", getPackageName());
            d.put("integrity_value", hex.toString());
            d.put("expected_value", EXPECTED_CERT_SHA256);
            d.put("signing_certificate_metadata", "signers=" + info.signatures.length);
            d.put("verification_result", hex.toString().equals(EXPECTED_CERT_SHA256) ? "PASSED" : "FAILED");
            Rasp.send("ME-13", "APPLICATION_INTEGRITY_CHECK", "RaspApp", d);
        } catch (Exception e) { e.printStackTrace(); }
    }

    // ME-04: every clipboard change while the app runs (length only, never the text)
    private void watchClipboard() {
        final ClipboardManager cb = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cb.addPrimaryClipChangedListener(new ClipboardManager.OnPrimaryClipChangedListener() {
            @Override
            public void onPrimaryClipChanged() {
                try {
                    ClipData clip = cb.getPrimaryClip();
                    int length = 0;
                    String type = "unknown";
                    if (clip != null && clip.getItemCount() > 0) {
                        CharSequence text = clip.getItemAt(0).getText();
                        length = text != null ? text.length() : 0;
                        type = clip.getDescription().getMimeType(0);
                    }
                    JSONObject d = new JSONObject();
                    d.put("operation", "WRITE");
                    d.put("data_type", type);
                    d.put("data_length", length);
                    d.put("status", "SUCCESS");
                    Rasp.send("ME-04", "CLIPBOARD_ACCESS", "RaspApp", d);
                } catch (Exception e) { e.printStackTrace(); }
            }
        });
    }
}