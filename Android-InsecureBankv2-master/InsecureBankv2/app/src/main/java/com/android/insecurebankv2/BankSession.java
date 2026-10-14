package com.android.insecurebankv2;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Base64;

import java.io.UnsupportedEncodingException;

/*
 * Centralised access to the two things every new feature needs:
 *
 *   1. the credentials the original application already persists in
 *      "mySharedPreferences" (Base64 username + AES/CBC password produced by
 *      DoLogin.saveCreds()), and
 *   2. the backend address stored by FilePrefActivity in the default preferences.
 *
 * The InsecureBankv2 protocol is that there is no token: every request re-reads and
 * re-decrypts the stored credentials. This helper keeps that behaviour byte-for-byte
 * compatible with DoTransfer/ChangePassword so the new screens plug into the existing
 * authentication model without changing it.
 */
public final class BankSession {

    public static final String MYPREFS = "mySharedPreferences";
    public static final String KEY_USERNAME = "EncryptedUsername";
    public static final String KEY_PASSWORD = "superSecurePassword";

    public static final String PREF_SERVER_IP = "serverip";
    public static final String PREF_SERVER_PORT = "serverport";

    public static final String PROTOCOL = "http://";

    private BankSession() {
    }

    /**
     * @return the stored (Base64 encoded) username or null when nobody is logged in.
     */
    public static String getEncryptedUsername(Context context) {
        SharedPreferences s = context.getSharedPreferences(MYPREFS, Context.MODE_PRIVATE);
        return s.getString(KEY_USERNAME, null);
    }

    /**
     * @return the plaintext username, or null when the user is not logged in.
     */
    public static String getUsername(Context context) {
        String encoded = getEncryptedUsername(context);
        if (encoded == null) {
            return null;
        }
        try {
            return new String(Base64.decode(encoded, Base64.DEFAULT), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * @return the plaintext password recovered from the local AES store, or null.
     */
    public static String getPassword(Context context) {
        SharedPreferences s = context.getSharedPreferences(MYPREFS, Context.MODE_PRIVATE);
        String encrypted = s.getString(KEY_PASSWORD, null);
        if (encrypted == null) {
            return null;
        }
        try {
            String plain = new CryptoClass().aesDeccryptedString(encrypted);
            // never let the plaintext leak into the event stream
            RaspEvent.registerSecret(plain);
            return plain;
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean isLoggedIn(Context context) {
        return getEncryptedUsername(context) != null;
    }

    /** Clears the local session. Used by the LOGOUT path. */
    public static void clear(Context context) {
        SharedPreferences s = context.getSharedPreferences(MYPREFS, Context.MODE_PRIVATE);
        s.edit().remove(KEY_USERNAME).remove(KEY_PASSWORD).commit();
        RaspEvent.registerSecret(null);
    }

    public static String serverIp(Context context) {
        return PreferenceManager.getDefaultSharedPreferences(context)
                .getString(PREF_SERVER_IP, null);
    }

    public static String serverPort(Context context) {
        return PreferenceManager.getDefaultSharedPreferences(context)
                .getString(PREF_SERVER_PORT, null);
    }

    public static boolean isServerConfigured(Context context) {
        String ip = serverIp(context);
        String port = serverPort(context);
        return ip != null && ip.length() > 0 && port != null && port.length() > 0;
    }

    /**
     * @return "http://ip:port" exactly as the original activities build it.
     */
    public static String baseUrl(Context context) {
        return PROTOCOL + serverIp(context) + ":" + serverPort(context);
    }
}
