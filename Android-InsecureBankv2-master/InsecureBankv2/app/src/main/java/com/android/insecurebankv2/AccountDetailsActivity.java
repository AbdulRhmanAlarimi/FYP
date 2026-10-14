package com.android.insecurebankv2;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;

import com.marcohc.toasteroid.Toasteroid;

import org.apache.http.NameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/*
 * ===========================================================================================
 *  FEATURE 1 - ACCOUNT DETAILS
 *
 *  Normal workflow : LOGIN -> ACCOUNT DETAILS -> LOGOUT
 *  Shows the account number, the account holder name, the current balance and the
 *  account type, plus one row per account the customer owns.
 *
 *  The whole screen is served by POST /getaccountdetails, which authenticates the caller
 *  and only ever returns rows owned by that user. There is no authorization defect here.
 *
 *  VULNERABILITY  : RASP-VULN-001 - sensitive account data written to the system log
 *                   (see logAccountDetails() below).
 * ===========================================================================================
 */
public class AccountDetailsActivity extends RaspBankActivity {

    private TextView holder;
    private TextView primaryAccount;
    private TextView primaryType;
    private TextView balance;
    private ListView accountList;
    private ArrayAdapter<String> adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_account_details);

        holder = (TextView) findViewById(R.id.textView_holder);
        primaryAccount = (TextView) findViewById(R.id.textView_primaryAccount);
        primaryType = (TextView) findViewById(R.id.textView_primaryType);
        balance = (TextView) findViewById(R.id.textView_balance);
        accountList = (ListView) findViewById(R.id.listView_accounts);

        adapter = new ArrayAdapter<String>(this, R.layout.item_row, R.id.rowText,
                new ArrayList<String>());
        accountList.setAdapter(adapter);

        Button refresh = (Button) findViewById(R.id.button_refresh);
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                loadAccounts(false);
            }
        });

        if (requireSession()) {
            loadAccounts(true);
        }
    }

    /**
     * @param fromResume true when the screen is opened for the first time, which is the
     *                   "ACCOUNT_VIEW" event, false for a manual refresh.
     */
    private void loadAccounts(final boolean fromResume) {
        List<NameValuePair> params = authParams();
        apiPost("/getaccountdetails", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                String ok = bodyOrNull(body, "Correct Credentials");
                if (ok == null) {
                    track(RaspEvent.ACCOUNT_VIEW, false, "server rejected the request");
                    toast("Could not load account details", false);
                    return;
                }
                try {
                    JSONObject json = new JSONObject(body);
                    String holderName = json.getString("holder_name");
                    String number = json.getString("account_number");
                    String type = json.getString("account_type");
                    int currentBalance = json.getInt("balance");
                    String currency = json.optString("currency", "USD");

                    holder.setText("Account Holder: " + holderName);
                    primaryAccount.setText("Account Number: " + number);
                    primaryType.setText("Account Type: " + type);
                    balance.setText("Current Balance: " + currentBalance + " " + currency);

                    List<String> rows = new ArrayList<String>();
                    JSONArray accounts = json.optJSONArray("accounts");
                    if (accounts != null) {
                        for (int i = 0; i < accounts.length(); i++) {
                            JSONObject a = accounts.getJSONObject(i);
                            rows.add(a.getString("account_number") + "  |  "
                                    + a.getString("type") + "  |  "
                                    + a.getString("balance") + " "
                                    + a.optString("currency", "USD"));
                        }
                    }
                    adapter.clear();
                    adapter.addAll(rows);
                    adapter.notifyDataSetChanged();

                    RaspEvent.ok(RaspEvent.ACCOUNT_VIEW, "AccountDetailsActivity", uname,
                            opId, "accounts=" + rows.size() + " balance=" + currentBalance);
                    RaspEvent.ok(RaspEvent.BALANCE_VIEW, "AccountDetailsActivity", uname,
                            opId, "account=" + number + " balance=" + currentBalance);

                    logAccountDetails(holderName, number, type, currentBalance, rows);

                    if (fromResume) {
                        track(RaspEvent.ACCOUNT_REFRESH, true, "screen opened");
                    }
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("AccountDetailsActivity", uname, opId,
                            "response parse: " + e.getMessage());
                    toast("Could not read account details", false);
                }
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                track(RaspEvent.ACCOUNT_VIEW, false, "transport " + message);
                toast("Server not reachable", false);
            }
        });
    }

    /* ==================================================================================
     *  VULNERABILITY ID : RASP-VULN-001
     *  FEATURE          : 1 - Account Details
     *  TYPE             : CWE-532 Insertion of Sensitive Information into Log File
     *                     (a.k.a. CWE-215 Insertion of Sensitive Information Into Debug
     *                     Information Files)
     *  COMPONENT        : AccountDetailsActivity.logAccountDetails()
     *  EXPECTED GOOD    : nothing, or at most a boolean "viewed=true". The account number
     *                     and the balance must never reach logcat, which is world readable
     *                     to any app holding READ_LOGS / to `adb logcat` / to any bug
     *                     report the user is asked to send.
     *  ACTUAL BEHAVIOUR : the full PAN-like account number, the holder name, the account
     *                     type and the live balance of every account are written to logcat
     *                     with Log.i(), which lands in the system buffer and is also
     *                     mirrored into /data/system/dropbox and crash reports.
     *  RUNTIME EVENTS   : ACCOUNT_VIEW (success) and BALANCE_VIEW (success) are emitted
     *                     first; the log lines follow, tagged "InsecureBankAccount".
     *  REPRODUCE        : log in -> open "Account Details" ->
     *                     adb logcat -s InsecureBankAccount:I
     *                     every field of the account is printed there.
     *  BLAST RADIUS     : disclosure only. No state is modified, the screen keeps working
     *                     and the backend is not involved.
     * ================================================================================== */
    private void logAccountDetails(String holderName, String number, String type,
                                   int currentBalance, List<String> allAccounts) {
        StringBuilder sb = new StringBuilder();
        sb.append("ACCOUNT DETAILS :: holder=").append(holderName);
        sb.append(" account_number=").append(number);
        sb.append(" account_type=").append(type);
        sb.append(" balance=").append(currentBalance);
        sb.append(" currency=USD");
        for (String row : allAccounts) {
            sb.append(" | account=").append(row);
        }
        Log.i("InsecureBankAccount", sb.toString());
        System.out.println("[AccountDetails] " + sb.toString());
        Toasteroid.show(this, "Account details refreshed", Toasteroid.STYLES.SUCCESS,
                Toasteroid.LENGTH_SHORT);
    }
}
