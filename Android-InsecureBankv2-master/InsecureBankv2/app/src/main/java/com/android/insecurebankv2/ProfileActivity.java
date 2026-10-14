package com.android.insecurebankv2;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.marcohc.toasteroid.Toasteroid;

import org.apache.http.NameValuePair;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/*
 * ===========================================================================================
 *  FEATURE 5 - PROFILE MANAGEMENT
 *
 *  Normal workflow : LOGIN -> PROFILE -> EDIT -> SAVE -> LOGOUT
 *  Also links to the pre-existing ChangePassword screen; changing the password there emits
 *  PASSWORD_CHANGE (see ChangePassword.java).
 *
 *  Backend  : /getprofile , /updateprofile
 *  The data handled here is FAKE seeded test data (see SEED_CONTACTS in the server), no
 *  real person is represented.
 *
 *  VULNERABILITY : RASP-VULN-005 - the profile is mirrored into insecure local storage and
 *                  into the system log. See dumpProfileToLocalStorage().
 * ===========================================================================================
 */
public class ProfileActivity extends RaspBankActivity {

    private static final String PROFILE_PREF_FILE = "insecurebankProfileCache";
    private static final String DUMP_DIR = "InsecureBankProfiles";

    private TextView usernameLabel;
    private TextView status;
    private EditText firstName;
    private EditText lastName;
    private EditText email;
    private EditText phone;
    private EditText address;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_profile);

        usernameLabel = (TextView) findViewById(R.id.textView_profileUser);
        status = (TextView) findViewById(R.id.textView_profileStatus);
        firstName = (EditText) findViewById(R.id.editText_firstName);
        lastName = (EditText) findViewById(R.id.editText_lastName);
        email = (EditText) findViewById(R.id.editText_email);
        phone = (EditText) findViewById(R.id.editText_phone);
        address = (EditText) findViewById(R.id.editText_address);

        Button save = (Button) findViewById(R.id.button_saveProfile);
        save.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                saveProfile();
            }
        });

        Button changePassword = (Button) findViewById(R.id.button_changePassword);
        changePassword.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                trackNav("ChangePassword");
                IntentBridge.openChangePassword(ProfileActivity.this, uname);
            }
        });

        Button refresh = (Button) findViewById(R.id.button_refreshProfile);
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                loadProfile();
            }
        });

        if (!requireSession()) {
            return;
        }
        loadProfile();
    }

    /* ======================================================================== view */

    private void loadProfile() {
        apiPost("/getprofile", authParams(), new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    track(RaspEvent.PROFILE_VIEW, false, "server rejected the request");
                    return;
                }
                try {
                    JSONObject json = new JSONObject(body);
                    usernameLabel.setText("Username: " + json.getString("username"));
                    firstName.setText(json.optString("first_name"));
                    lastName.setText(json.optString("last_name"));
                    email.setText(json.optString("email"));
                    phone.setText(json.optString("phone"));
                    address.setText(json.optString("address"));

                    RaspEvent.ok(RaspEvent.PROFILE_VIEW, "ProfileActivity", uname, opId,
                            "fields=6 source=server");
                    dumpProfileToLocalStorage(json);
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("ProfileActivity", uname, opId,
                            "profile parse: " + e.getMessage());
                    toast("Could not read the profile", false);
                }
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("ProfileActivity", uname, opId, "profile transport " + message);
            }
        });
    }

    /* ======================================================================== save */

    private void saveProfile() {
        final String f = firstName.getText().toString();
        final String l = lastName.getText().toString();
        final String m = email.getText().toString();
        final String p = phone.getText().toString();
        final String a = address.getText().toString();

        List<NameValuePair> params = authParams();
        addParam(params, "first_name", f);
        addParam(params, "last_name", l);
        addParam(params, "email", m);
        addParam(params, "phone", p);
        addParam(params, "address", a);

        apiPost("/updateprofile", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                boolean ok = body != null && body.indexOf("Profile Updated") != -1;
                RaspEvent.log(RaspEvent.PROFILE_UPDATE, "ProfileActivity", uname,
                        ok ? RaspEvent.RESULT_SUCCESS : RaspEvent.RESULT_FAILURE, opId,
                        "fields_changed=" + changedFields(f, l, m, p, a));
                toast(ok ? "Profile saved" : "Profile could not be saved", ok);
                if (ok) {
                    loadProfile();
                }
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.fail(RaspEvent.PROFILE_UPDATE, "ProfileActivity", uname, opId,
                        "transport=" + message);
            }
        });
    }

    /* ==================================================================================
     *  VULNERABILITY ID : RASP-VULN-005
     *  FEATURE          : 5 - Profile Management
     *  TYPE             : CWE-312 Cleartext Storage of Sensitive Information together with
     *                     CWE-276 Incorrect Default Permissions and CWE-532 (log copy)
     *  COMPONENT        : ProfileActivity.dumpProfileToLocalStorage()
     *  EXPECTED GOOD    : nothing is written outside the application sandbox. If an offline
     *                     copy is genuinely needed it must be encrypted with a per-install
     *                     key (the CryptoClass already present in this project would do)
     *                     and written with MODE_PRIVATE.
     *  ACTUAL BEHAVIOUR : every successful profile view/save copies name, e-mail, phone
     *                     number and address, in clear text, to
     *                       (a) /sdcard/InsecureBankProfiles/Profile_<user>.txt
     *                           world readable by every application and by any adb session
     *                       (b) a MODE_WORLD_READABLE SharedPreferences file
     *                       (c) the system log, tag "InsecureBankProfile"
     *  RUNTIME EVENTS   : PROFILE_VIEW / PROFILE_UPDATE (result=success) are emitted just
     *                     before each dump; the event itself never carries the profile so
     *                     the leak is not visible in the event stream.
     *  REPRODUCE        : log in -> Profile -> Refresh, then
     *                       adb shell cat /sdcard/InsecureBankProfiles/Profile_dinesh.txt
     *                     or on the device with a file manager / any app holding
     *                     READ_EXTERNAL_STORAGE.
     *                     adb logcat -s InsecureBankProfile:I shows the same content.
     *  SAFETY           : the stored values are the fake seeded test contacts, no real
     *                     personal data is involved, and nothing is transmitted anywhere.
     *                     The dump is best effort: if the filesystem is unavailable the
     *                     application keeps working normally.
     * ================================================================================== */
    private void dumpProfileToLocalStorage(JSONObject profile) {
        String fullName = profile.optString("full_name");
        String mail = profile.optString("email");
        String telephone = profile.optString("phone");
        String home = profile.optString("address");
        String user = profile.optString("username", uname);

        String body = "username=" + user + "\n"
                + "full_name=" + fullName + "\n"
                + "email=" + mail + "\n"
                + "phone=" + telephone + "\n"
                + "address=" + home + "\n"
                + "captured=" + System.currentTimeMillis() + "\n";

        //  (a) clear text file on shared storage
        try {
            File dir = new File(Environment.getExternalStorageDirectory(), DUMP_DIR);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            writeFile(new File(dir, "Profile_" + user + ".txt"), body);
        } catch (Throwable t) {
            // best effort, shared storage may be unavailable or read-only
        }
        try {
            //  the app specific external directory always works and is still readable
            //  through `adb pull /sdcard/Android/data/<pkg>/files/`
            File dir = getExternalFilesDir(DUMP_DIR);
            if (dir != null) {
                writeFile(new File(dir, "Profile_" + user + ".txt"), body);
            }
        } catch (Throwable t) {
            // best effort
        }

        //  (b) world readable preferences
        try {
            SharedPreferences prefs = getSharedPreferences(PROFILE_PREF_FILE,
                    android.content.Context.MODE_WORLD_READABLE);
            prefs.edit()
                    .putString("username", user)
                    .putString("full_name", fullName)
                    .putString("email", mail)
                    .putString("phone", telephone)
                    .putString("address", home)
                    .commit();
        } catch (Throwable t) {
            // best effort
        }

        //  (c) system log
        Log.i("InsecureBankProfile", "PROFILE " + body.replace('\n', ' '));
        System.out.println("[Profile] " + body.replace('\n', ' '));

        status.setText("Profile loaded");
        RaspEvent.ok(RaspEvent.NAVIGATE, "ProfileActivity", uname, opId,
                "profile_cached_to_device=1");
    }

    private static void writeFile(File target, String body) throws IOException {
        BufferedWriter out = new BufferedWriter(new FileWriter(target, false));
        try {
            out.write(body);
            out.flush();
        } finally {
            out.close();
        }
    }

    private static int changedFields(String f, String l, String m, String p, String a) {
        int n = 0;
        if (f != null && f.length() > 0) {
            n++;
        }
        if (l != null && l.length() > 0) {
            n++;
        }
        if (m != null && m.length() > 0) {
            n++;
        }
        if (p != null && p.length() > 0) {
            n++;
        }
        if (a != null && a.length() > 0) {
            n++;
        }
        return n;
    }

    /** tiny indirection so the Intent plumbing stays in one place */
    static class IntentBridge {
        static void openChangePassword(android.app.Activity from, String user) {
            android.content.Intent i = new android.content.Intent(from,
                    ChangePassword.class);
            i.putExtra("uname", user);
            from.startActivity(i);
        }
    }
}
