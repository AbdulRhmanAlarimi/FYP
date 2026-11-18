package com.intellirasp.detector;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

/**
 * AS09 - APK tampering detection.
 * Hashes the running APK (SHA-256) and compares it to the official hash stored
 * on the RASP backend (Postgres), NOT inside the APK (embedding would change the hash).
 */
public class AS09IntegrityRule {

    private static final String TAG = "IntelliRASP-AS09";
    // Same host as Rasp.SERVER — official baseline lives on the SIEM backend.
    private static final String TRUSTED_HASH_URL =
            "http://10.0.2.2:8000/api/integrity/trusted-hash";

    public static class Result {
        public final boolean passed;
        public final String currentHash;
        public final String trustedHash;
        public final String detail;

        public Result(boolean passed, String currentHash, String trustedHash, String detail) {
            this.passed = passed;
            this.currentHash = currentHash;
            this.trustedHash = trustedHash;
            this.detail = detail;
        }
    }

    /** SHA-256 of the APK file currently installed on the device. */
    public static String getCurrentHash(Context context) throws Exception {
        String apkPath = context.getApplicationInfo().sourceDir;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (FileInputStream fis = new FileInputStream(apkPath)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        StringBuilder hash = new StringBuilder();
        for (byte b : digest.digest()) {
            hash.append(String.format("%02x", b & 0xff));
        }
        return hash.toString();
    }

    /** Official hash from the backend database (empty string if none configured). */
    public static String fetchTrustedHash() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(TRUSTED_HASH_URL).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        try {
            int code = conn.getResponseCode();
            InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (in == null) {
                throw new Exception("empty response from integrity API (HTTP " + code + ")");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line);
            reader.close();
            if (code >= 400) {
                throw new Exception("integrity API HTTP " + code + ": " + body);
            }
            JSONObject json = new JSONObject(body.toString());
            return json.optString("sha256", "").trim().toLowerCase();
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Compare installed APK hash to the official backend baseline.
     * Must be called off the main thread (network + file I/O).
     */
    public static Result check(Context context) {
        try {
            String currentHash = getCurrentHash(context);
            String trustedHash = fetchTrustedHash();

            if (currentHash == null || currentHash.length() == 0) {
                Log.e(TAG, "Integrity verification failed: could not hash APK");
                return new Result(false, currentHash, trustedHash, "current_hash_missing");
            }
            if (trustedHash == null || trustedHash.length() == 0) {
                Log.e(TAG, "Integrity verification failed: no trusted hash on server");
                return new Result(false, currentHash, "", "trusted_hash_not_configured");
            }
            if (!currentHash.equalsIgnoreCase(trustedHash)) {
                Log.e(TAG, "APK TAMPERING DETECTED! current=" + currentHash
                        + " trusted=" + trustedHash);
                return new Result(false, currentHash, trustedHash, "hash_mismatch");
            }

            Log.i(TAG, "APK integrity verified");
            return new Result(true, currentHash, trustedHash, "ok");
        } catch (Exception e) {
            Log.e(TAG, "Integrity check failed", e);
            return new Result(false, "", "", "check_error: " + e.getMessage());
        }
    }

    /** Convenience boolean wrapper (true only when hashes match). */
    public static boolean matches(Context context) {
        return check(context).passed;
    }

    // v2 rule: explicit v2 integrity verification entrypoints (backend-anchored baseline).
    public static Result check_v2(Context context) {
        Result result = check(context);
        Log.i(TAG, "check_v2 result=" + result.passed + " detail=" + result.detail);
        return result;
    }

    public static boolean matches_v2(Context context) {
        return check_v2(context).passed;
    }
}
