package com.android.insecurebankv2;

import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Spinner;
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
 *  FEATURE 6 - DEPOSIT MONEY
 *
 *  Normal workflow : LOGIN -> DEPOSIT -> ACCOUNT -> AMOUNT -> CONFIRM -> BALANCE UPDATED
 *  On success the server credits the account, writes a DEPOSIT row in the transaction
 *  history and returns the new balance, which the screen displays.
 *
 *  Backend  : /getmyaccounts , /deposit
 *
 *  VULNERABILITY : RASP-VULN-006 - business logic / missing authorization. The screen can
 *                  be pointed at an account that does not belong to the caller and the
 *                  amount is never checked for sign or magnitude. See doDeposit() and
 *                  AndroLabServer/app.py :: deposit().
 * ===========================================================================================
 */
public class DepositActivity extends RaspBankActivity {

    private Spinner accountSpinner;
    private EditText accountOverride;
    private EditText amount;
    private TextView selected;
    private TextView result;
    private ListView depositList;
    private ArrayAdapter<String> listAdapter;

    private List<String> myAccounts = new ArrayList<String>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_deposit);

        accountSpinner = (Spinner) findViewById(R.id.spinner_depositAccount);
        accountOverride = (EditText) findViewById(R.id.editText_accountOverride);
        amount = (EditText) findViewById(R.id.editText_depositAmount);
        selected = (TextView) findViewById(R.id.textView_selectedAccount);
        result = (TextView) findViewById(R.id.textView_depositResult);
        depositList = (ListView) findViewById(R.id.listView_deposits);

        listAdapter = new ArrayAdapter<String>(this, R.layout.item_row, R.id.rowText,
                new ArrayList<String>());
        depositList.setAdapter(listAdapter);

        Button deposit = (Button) findViewById(R.id.button_deposit);
        deposit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                doDeposit();
            }
        });

        Button refresh = (Button) findViewById(R.id.button_refreshAccounts);
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                loadAccounts();
            }
        });

        accountSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                // TODO Auto-generated method stub
                Object item = parent.getItemAtPosition(position);
                selected.setText("Selected account: " + item);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                // TODO Auto-generated method stub
            }
        });

        if (!requireSession()) {
            return;
        }
        loadAccounts();
    }

    /* ====================================================================== accounts */

    private void loadAccounts() {
        apiPost("/getmyaccounts", authParams(), new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    RaspEvent.error("DepositActivity", uname, opId, "accounts rejected");
                    return;
                }
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("accounts");
                    myAccounts.clear();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject a = arr.getJSONObject(i);
                            myAccounts.add(a.getString("account_number") + " ("
                                    + a.getString("type") + ", balance " + a.getString("balance") + ")");
                        }
                    }
                    ArrayAdapter<String> adapter = new ArrayAdapter<String>(DepositActivity.this,
                            android.R.layout.simple_spinner_item, myAccounts);
                    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
                    accountSpinner.setAdapter(adapter);
                    RaspEvent.ok(RaspEvent.BALANCE_VIEW, "DepositActivity", uname, opId,
                            "accounts=" + myAccounts.size());
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("DepositActivity", uname, opId,
                            "accounts parse: " + e.getMessage());
                }
                loadRecentDeposits();
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("DepositActivity", uname, opId, "accounts transport " + message);
            }
        });
    }

    private void loadRecentDeposits() {
        apiPost("/gettransactions", authParams(), new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    return;
                }
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("transactions");
                    List<String> rows = new ArrayList<String>();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject t = arr.getJSONObject(i);
                            if ("DEPOSIT".equals(t.optString("type"))) {
                                rows.add(t.optString("date") + " | " + t.optString("direction")
                                        + " | " + t.optString("amount")
                                        + " | account " + t.optString("account_number"));
                            }
                        }
                    }
                    listAdapter.clear();
                    listAdapter.addAll(rows);
                    listAdapter.notifyDataSetChanged();
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("DepositActivity", uname, opId,
                            "deposits parse: " + e.getMessage());
                }
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("DepositActivity", uname, opId, "deposits transport " + message);
            }
        });
    }

    /* ======================================================================== deposit */

    /* ==================================================================================
     *  VULNERABILITY ID : RASP-VULN-006
     *  FEATURE          : 6 - Deposit Money
     *  TYPE             : CWE-862 Missing Authorization combined with CWE-20 Improper
     *                     Input Validation (business logic)
     *  COMPONENT        : DepositActivity.doDeposit()  (client, builds the request)
     *                     AndroLabServer/app.py :: deposit()  (server, accepts it)
     *  EXPECTED GOOD    : the client only ever offers the accounts the caller owns, and the
     *                     server independently verifies that the requested account_number
     *                     belongs to the authenticated user, that the amount is numeric,
     *                     strictly positive and inside a per-transaction ceiling.
     *  ACTUAL BEHAVIOUR : the "Or enter another account number" field is accepted as is and
     *                     the server never compares the owner of the target account with the
     *                     caller, so any account in the fixture can be credited by any
     *                     logged in customer. The amount is additionally accepted with a
     *                     negative sign, which reverses the direction of the movement.
     *  RUNTIME EVENTS   : DEPOSIT with result=success and a detail that carries
     *                     account=<n> owner_accounts=<a,b,c> foreign_account=true/false
     *                     amount="<raw>" amount_numeric=<bool> negative=<bool>.
     *                     `foreign_account=true` together with a success is the observable
     *                     signature of the attack; it never occurs in the benign workflow.
     *  REPRODUCE        : log in as dinesh -> Deposit Money, then
     *                       a) type 555555555 (jack's account) into
     *                          "Or enter another account number" and 5000 into the amount
     *                       b) or simply type -1 into the amount
     *                     and press "Confirm Deposit". Both report success.
     *  SAFETY           : the effect is confined to the local research fixture
     *                     (AndroLabServer/mydb.db). An unknown account number still
     *                     returns a clean error, the balance is never left undefined and
     *                     the application keeps working normally.
     * ================================================================================== */
    private void doDeposit() {
        final String override = accountOverride.getText().toString().trim();
        Object picked = accountSpinner.getSelectedItem();

        //  Intentionally NOT validated - see the block comment above.
        final String accountNumber = override.length() > 0
                ? override
                : (picked == null ? "" : String.valueOf(picked).split(" ")[0]);
        final String rawAmount = amount.getText().toString();

        final boolean foreign = !myAccounts.isEmpty() && !isOwnedByCaller(accountNumber);
        final boolean negative = rawAmount.startsWith("-");

        RaspEvent.ok(RaspEvent.DEPOSIT, "DepositActivity", uname, opId,
                "stage=submit account=" + accountNumber
                        + " foreign_account=" + foreign
                        + " amount=\"" + rawAmount + "\""
                        + " amount_numeric=" + isNumeric(rawAmount)
                        + " negative=" + negative);

        List<NameValuePair> params = authParams();
        addParam(params, "account_number", accountNumber);
        addParam(params, "amount", rawAmount);

        apiPost("/deposit", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                boolean ok = body != null && body.indexOf("Deposit Successful") != -1;
                String newBalance = "";
                String account = accountNumber;
                if (ok) {
                    try {
                        JSONObject json = new JSONObject(body);
                        newBalance = String.valueOf(json.optInt("balance"));
                        account = json.optString("account_number", accountNumber);
                    } catch (JSONException e) {
                        // TODO Auto-generated catch block
                        newBalance = "";
                    }
                }
                RaspEvent.log(RaspEvent.DEPOSIT, "DepositActivity", uname,
                        ok ? RaspEvent.RESULT_SUCCESS : RaspEvent.RESULT_FAILURE, opId,
                        "stage=result account=" + account
                                + " foreign_account=" + foreign
                                + " amount=\"" + rawAmount + "\""
                                + " amount_numeric=" + isNumeric(rawAmount)
                                + " negative=" + negative
                                + " balance=" + newBalance);
                if (ok) {
                    result.setText("Deposit successful. New balance: " + newBalance);
                    Toasteroid.show(DepositActivity.this, "Deposit successful",
                            Toasteroid.STYLES.SUCCESS, Toasteroid.LENGTH_SHORT);
                    RaspEvent.ok(RaspEvent.BALANCE_VIEW, "DepositActivity", uname, opId,
                            "account=" + account + " balance=" + newBalance);
                } else {
                    result.setText("Deposit could not be completed");
                    Toasteroid.show(DepositActivity.this, "Deposit failed",
                            Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_SHORT);
                }
                loadAccounts();
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.fail(RaspEvent.DEPOSIT, "DepositActivity", uname, opId,
                        "stage=result transport=" + message);
                result.setText("Server not reachable");
            }
        });
    }

    /* =========================================================================== utils */

    private boolean isOwnedByCaller(String accountNumber) {
        for (String row : myAccounts) {
            if (row.startsWith(accountNumber + " ")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isNumeric(String s) {
        if (s == null || s.length() == 0) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
