package com.android.insecurebankv2;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.apache.http.NameValuePair;

import java.util.List;
import java.util.regex.Pattern;

/*
 * ===========================================================================================
 *  USER SIGNUP - self-service registration
 *
 *  Normal workflow : LOGIN SCREEN -> CREATE USER -> FILL FORM -> CREATE ACCOUNT -> LOG IN
 *
 *  This screen replaces the Work-In-Progress stub that the original InsecureBankv2 shipped
 *  in LoginActivity.createUser(), which only showed a toast saying the feature was not
 *  finished yet.
 *
 *  Backend  : /signup
 *  The server creates the `users` row and allocates a fresh "from" and "to" account for the
 *  new customer, both pre-funded, so all six features work immediately after the first
 *  login. Nothing is created locally and no session is opened here: the user still has to
 *  log in through the normal DoLogin path afterwards.
 *
 *  NO INTENTIONAL VULNERABILITY
 *  ---------------------------
 *  Signup is the one screen of this build that is deliberately well behaved, and it must
 *  stay that way: docs/INTENTIONAL_VULNERABILITIES.md lists exactly six findings and
 *  signup is not one of them. The checks below mirror AndroLabServer/app.py::validate_signup()
 *  so the user gets immediate feedback, but the server is the authority - it re-validates
 *  everything and its rejection message is what the screen shows.
 *
 *  PASSWORD HANDLING
 *  -----------------
 *  The plaintext password never reaches RaspEvent, never reaches the log and is never put
 *  in an Intent. `detail` only ever carries lengths and boolean flags, exactly like the
 *  pre-existing PASSWORD_CHANGE event. The username *is* carried: it is the label of the
 *  trace and, at this point in the flow, it is data the user is inventing rather than
 *  data that was disclosed.
 * ===========================================================================================
 */
public class SignUpActivity extends RaspBankActivity {

    /** same rules as SIGNUP_USERNAME_RE in AndroLabServer/app.py */
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9._-]{3,50}$");
    private static final int MIN_PASSWORD = 6;

    private static final String COMPONENT = "SignUpActivity";

    private EditText username;
    private EditText password;
    private EditText confirm;
    private EditText firstName;
    private EditText lastName;
    private EditText email;
    private EditText phone;
    private EditText address;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_signup);

        username = (EditText) findViewById(R.id.editText_signupUsername);
        password = (EditText) findViewById(R.id.editText_signupPassword);
        confirm = (EditText) findViewById(R.id.editText_signupConfirm);
        firstName = (EditText) findViewById(R.id.editText_signupFirstName);
        lastName = (EditText) findViewById(R.id.editText_signupLastName);
        email = (EditText) findViewById(R.id.editText_signupEmail);
        phone = (EditText) findViewById(R.id.editText_signupPhone);
        address = (EditText) findViewById(R.id.editText_signupAddress);
        status = (TextView) findViewById(R.id.textView_signupStatus);

        Button create = (Button) findViewById(R.id.button_createAccount);
        create.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                submit();
            }
        });

        //  Unlike every other screen of this build there is no session to require, so
        //  requireSession() is deliberately not called. The only precondition is that a
        //  backend address has been configured.
        if (!BankSession.isServerConfigured(this)) {
            toast("Server path/port not set!!", false);
            RaspEvent.error(COMPONENT, "anonymous", opId, "server address not configured");
            startActivity(new Intent(this, FilePrefActivity.class));
            finish();
        }
    }

    /* ======================================================================== validate */

    /**
     * Client side mirror of the server rules.
     *
     * @return null when the form may be sent, otherwise the message for the user.
     */
    private String checkForm(String user, String pass, String pass2) {
        if (user.length() == 0) {
            return "Username is required";
        }
        if (!USERNAME_PATTERN.matcher(user).matches()) {
            return "Username must be 3-50 characters using letters, digits, dot, underscore or dash";
        }
        if (pass.length() == 0) {
            return "Password is required";
        }
        if (pass.length() < MIN_PASSWORD) {
            return "Password must be at least " + MIN_PASSWORD + " characters";
        }
        if (!pass.equals(pass2)) {
            return "Passwords do not match";
        }
        return null;
    }

    /* ========================================================================== submit */

    private void submit() {
        final String user = username.getText().toString().trim();
        final String pass = password.getText().toString();
        final String pass2 = confirm.getText().toString();

        final String problem = checkForm(user, pass, pass2);
        if (problem != null) {
            RaspEvent.fail(RaspEvent.SIGNUP_FAILURE, COMPONENT, user, opId,
                    "stage=client reason=policy username_len=" + user.length()
                            + " password_len=" + pass.length()
                            + " password_confirmed=" + pass.equals(pass2));
            status.setText(problem);
            toast(problem, false);
            return;
        }

        status.setText("Creating your account...");

        RaspEvent.ok(RaspEvent.SIGNUP_ATTEMPT, COMPONENT, user, opId,
                "username_len=" + user.length()
                        + " password_len=" + pass.length()
                        + " password_confirmed=true"
                        + " has_email=" + (email.getText().toString().trim().length() > 0));

        List<NameValuePair> params = new java.util.ArrayList<NameValuePair>(8);
        addParam(params, "username", user);
        addParam(params, "password", pass);
        addParam(params, "confirm_password", pass2);
        addParam(params, "first_name", firstName.getText().toString().trim());
        addParam(params, "last_name", lastName.getText().toString().trim());
        addParam(params, "email", email.getText().toString().trim());
        addParam(params, "phone", phone.getText().toString().trim());
        addParam(params, "address", address.getText().toString().trim());

        apiPost("/signup", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                handleServerResult(body, user);
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.fail(RaspEvent.SIGNUP_FAILURE, COMPONENT, user, opId,
                        "stage=server reason=transport");
                RaspEvent.error(COMPONENT, user, opId, "signup transport " + message);
                status.setText("Could not reach the server");
                toast("Could not reach the server", false);
            }
        });
    }

    private void handleServerResult(String body, String user) {
        if (bodyOrNull(body, "User created successfully") == null) {
            //  The server refused. Its message is already free of anything sensitive, so it
            //  is both shown to the user and recorded as the reason.
            String reason = extractMessage(body);
            RaspEvent.fail(RaspEvent.SIGNUP_FAILURE, COMPONENT, user, opId,
                    "stage=server reason=rejected server=\"" + reason + "\"");
            status.setText(reason);
            toast(reason, false);
            return;
        }

        RaspEvent.ok(RaspEvent.SIGNUP_SUCCESS, COMPONENT, user, opId,
                "stage=server accounts_provisioned=2");

        status.setText("Account created, you can log in now");
        toast("Account created", true);

        //  Hand the username back to the login screen so only the password has to be typed.
        //  The password itself is deliberately not passed between activities.
        Intent result = new Intent();
        result.putExtra("signup_username", user);
        setResult(RESULT_OK, result);
        finish();
    }

    /**
     * @return the `message` field of the JSON body, or a short generic string when the body
     * is not the JSON this endpoint produces. Never throws - a malformed response must not
     * take the screen down.
     */
    private static String extractMessage(String body) {
        if (body == null || body.length() == 0) {
            return "The account could not be created";
        }
        try {
            return new org.json.JSONObject(body).optString("message",
                    "The account could not be created");
        } catch (org.json.JSONException e) {
            // TODO Auto-generated catch block
            RaspEvent.error(COMPONENT, "anonymous", RaspEvent.newOpId(),
                    "signup response parse: " + e.getMessage());
            return "The account could not be created";
        }
    }

    /* ============================================================================== menu */

    /**
     * This screen runs before authentication, so there may be no session to end. Only the
     * LOGOUT event is conditional on one existing; the credential wipe and the bounce to
     * the login screen are unconditional.
     */
    @Override
    protected void performLogout() {
        if (BankSession.isLoggedIn(this)) {
            RaspEvent.ok(RaspEvent.LOGOUT, COMPONENT, uname, opId, "menu=restart");
        }
        BankSession.clear(this);
        Intent i = new Intent(getBaseContext(), LoginActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        finish();
    }
}
