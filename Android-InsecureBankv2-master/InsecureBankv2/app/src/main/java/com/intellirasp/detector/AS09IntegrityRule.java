package com.intellirasp.detector;

import android.content.Context;
import android.util.Log;

import java.io.FileInputStream;
import java.security.MessageDigest;

public class AS09IntegrityRule {

    private static final String TAG = "IntelliRASP-AS09";
    
    // a function that plays the role of getting the hash of the running app
    private static String getCurrentHash(Context context) throws Exception {

        // getting the running app sha256
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
	//building the hash variable
        for (byte b : digest.digest()) {
            hash.append(String.format("%02x", b & 0xff));
        }

        return hash.toString();
    }
    
    // true if the hashes match false if the hash changed
    public static boolean check(Context context) {

        try {
            // getting the hash into the variable to compare 
            String currentHash = getCurrentHash(context);

            
            String trustedHash = null; // i need the hash from the database or wherever you see it is secure to put the officail hash in 

            if (currentHash == null || trustedHash == null) {
                Log.e(TAG, "Integrity verification failed");
                return false;
            }

            if (!currentHash.equalsIgnoreCase(trustedHash)) {
                Log.e(TAG, "APK TAMPERING DETECTED!");
                return false;
            }

            Log.i(TAG, "APK integrity verified");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Integrity check failed", e);
            return false;
        }
    }

    
}
