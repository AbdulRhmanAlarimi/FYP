package com.android.insecurebankv2;

import android.app.Activity;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import com.marcohc.toasteroid.Toasteroid;

import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * Common base for the six new banking screens.
 *
 * It does exactly three things and deliberately nothing else:
 *   1. resolves the logged in user from the credentials the original application
 *      already stores (BankSession) so every screen speaks the same protocol;
 *   2. performs a background url-encoded POST through the same deprecated Apache
 *      HttpClient stack that DoLogin/DoTransfer/ChangePassword use, and delivers the
 *      result back on the UI thread;
 *   3. emits a consistent IntelliRASP event for every user action.
 *
 * The original activities are NOT refactored onto this class - they are untouched, they
 * only call the static RaspEvent helpers directly.
 */
public abstract class RaspBankActivity extends Activity {

    /** name written into the "component" field of every event produced by this screen */
    private final String component = this.getClass().getSimpleName();

    protected String uname;
    protected String opId = RaspEvent.newOpId();

    /** result of a backend round trip, always delivered on the UI thread */
    public interface ApiCallback {
        void onResult(String body);

        void onError(String message);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        if (intent != null) {
            String fromIntent = intent.getStringExtra("uname");
            if (fromIntent != null && fromIntent.length() > 0) {
                uname = fromIntent;
            }
        }
        if (uname == null) {
            uname = BankSession.getUsername(this);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (uname == null) {
            uname = BankSession.getUsername(this);
        }
    }

    /* ==================================================================== session guards */

    /**
     * Screens call this once their views exist. A missing session (cold start, task
     * restored from recents after a restart, ...) sends the user back to the login
     * screen instead of crashing on a null username.
     *
     * @return true when the screen may continue.
     */
    protected boolean requireSession() {
        if (uname == null || uname.length() == 0) {
            RaspEvent.fail(RaspEvent.SESSION_EXPIRED, component, "anonymous", opId,
                    "no local session");
            Toasteroid.show(this, "Please log in first", Toasteroid.STYLES.WARNING,
                    Toasteroid.LENGTH_SHORT);
            Intent i = new Intent(getApplicationContext(), LoginActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            startActivity(i);
            finish();
            return false;
        }
        if (!BankSession.isServerConfigured(this)) {
            Toasteroid.show(this, "Server path/port not set!!", Toasteroid.STYLES.ERROR,
                    Toasteroid.LENGTH_SHORT);
            RaspEvent.error(component, uname, opId, "server address not configured");
            Intent i = new Intent(getApplicationContext(), FilePrefActivity.class);
            startActivity(i);
            finish();
            return false;
        }
        return true;
    }

    /* =========================================================================== events */

    protected void track(String event, boolean success, String detail) {
        RaspEvent.log(event, component, uname, success ? RaspEvent.RESULT_SUCCESS
                : RaspEvent.RESULT_FAILURE, opId, detail);
    }

    protected void track(String event, boolean success) {
        track(event, success, null);
    }

    protected void trackNav(String target) {
        RaspEvent.ok(RaspEvent.NAVIGATE, component, uname, opId, "to=" + target);
    }

    /* ============================================================================= http */

    /**
     * @return a fresh parameter list already carrying username + password, matching the
     * parameter names the existing endpoints expect.
     */
    protected List<NameValuePair> authParams() {
        List<NameValuePair> pairs = new ArrayList<NameValuePair>(6);
        String user = uname != null ? uname : BankSession.getUsername(this);
        String pass = BankSession.getPassword(this);
        pairs.add(new org.apache.http.message.BasicNameValuePair("username", user == null ? "" : user));
        pairs.add(new org.apache.http.message.BasicNameValuePair("password", pass == null ? "" : pass));
        return pairs;
    }

    protected static void addParam(List<NameValuePair> pairs, String name, String value) {
        pairs.add(new org.apache.http.message.BasicNameValuePair(name, value == null ? "" : value));
    }

    /**
     * Performs the POST off the UI thread and hands the raw body back on the UI thread.
     * The body is what the original code would have received too, so response handling
     * stays identical to DoTransfer.
     */
    protected void apiPost(final String endpoint, final List<NameValuePair> params,
                           final ApiCallback callback) {
        final String url = BankSession.baseUrl(this) + endpoint;
        RaspEvent.ok(RaspEvent.SERVER_REQUEST, component, uname, opId, endpoint);

        new AsyncTask<String, String, String>() {
            String failure = null;

            @Override
            protected String doInBackground(String... args) {
                HttpClient httpclient = new DefaultHttpClient();
                HttpPost httppost = new HttpPost(url);
                try {
                    httppost.setEntity(new UrlEncodedFormEntity(params));
                } catch (UnsupportedEncodingException e) {
                    failure = "encoding";
                    return null;
                }
                InputStream in = null;
                try {
                    in = httpclient.execute(httppost).getEntity().getContent();
                    String body = convertStreamToString(in);
                    RaspEvent.ok(RaspEvent.SERVER_RESPONSE, component, uname, opId,
                            endpoint + " bytes=" + body.length());
                    return body == null ? "" : body.replace("\n", "");
                } catch (IOException e) {
                    failure = "io";
                    RaspEvent.error(component, uname, opId, endpoint + " transport failure");
                    return null;
                } catch (Exception e) {
                    failure = "parse";
                    return null;
                } finally {
                    if (in != null) {
                        try {
                            in.close();
                        } catch (IOException ignored) {
                        }
                    }
                }
            }

            @Override
            protected void onPostExecute(String result) {
                if (result == null) {
                    callback.onError(failure == null ? "error" : failure);
                } else {
                    callback.onResult(result);
                }
            }
        }.execute(endpoint);
    }

    /**
     * Identical to the private helper duplicated in DoLogin/DoTransfer/ChangePassword.
     */
    protected static String convertStreamToString(InputStream in) throws IOException {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            reader = new BufferedReader(new InputStreamReader(in));
        }
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line + "\n");
        }
        in.close();
        return sb.toString();
    }

    /* ============================================================== shared list parsing */

    /**
     * @return the raw body only when it carries the expected success marker, otherwise null.
     * Mirrors the `result.indexOf("...")` style used by the original screens.
     */
    protected static String bodyOrNull(String body, String successMarker) {
        if (body != null && successMarker != null && body.indexOf(successMarker) != -1) {
            return body;
        }
        return null;
    }

    protected void toast(String message, boolean success) {
        Toasteroid.show(this, message, success ? Toasteroid.STYLES.SUCCESS
                : Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_SHORT);
    }

    /* ========================================================================== the menu */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            callPreferences();
            return true;
        } else if (id == R.id.action_exit) {
            performLogout();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void callPreferences() {
        Intent i = new Intent(this, FilePrefActivity.class);
        startActivity(i);
    }

    /**
     * Emits LOGOUT, drops the local session and returns to the login screen.
     */
    protected void performLogout() {
        RaspEvent.ok(RaspEvent.LOGOUT, component, uname, opId, "menu=restart");
        BankSession.clear(this);
        Intent i = new Intent(getBaseContext(), LoginActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        finish();
    }

    /**
     * Opens another screen of this application, tagging the navigation event.
     */
    protected void open(Class<?> target, String tag) {
        trackNav(tag);
        Intent i = new Intent(getApplicationContext(), target);
        if (uname != null) {
            i.putExtra("uname", uname);
        }
        i.putExtra("op_id", opId);
        startActivity(i);
    }
}
