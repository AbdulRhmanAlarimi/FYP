package com.android.insecurebankv2;

import android.os.Bundle;
import android.view.View;
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
 *  FEATURE 4 - BILL PAYMENT
 *
 *  Normal workflow : LOGIN -> BILL PAYMENT -> CATEGORY -> BILL NUMBER -> AMOUNT -> CONFIRM
 *                    -> SUCCESS -> PAYMENT HISTORY
 *
 *  Backend       : /getbillcategories , /getmyaccounts , /paybill , /getbillhistory
 *
 *  VULNERABILITY  : RASP-VULN-004 - missing input validation, on the client
 *                   (doPayBill) and on the server (AndroLabServer/app.py :: paybill).
 *                   See the block comment above doPayBill().
 * ===========================================================================================
 */
public class BillPaymentActivity extends RaspBankActivity {

    private Spinner categorySpinner;
    private Spinner accountSpinner;
    private EditText billNumber;
    private EditText amount;
    private TextView result;
    private ListView historyList;
    private ArrayAdapter<String> historyAdapter;

    private List<String> payerAccounts = new ArrayList<String>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bill_payment);

        categorySpinner = (Spinner) findViewById(R.id.spinner_category);
        accountSpinner = (Spinner) findViewById(R.id.spinner_payerAccount);
        billNumber = (EditText) findViewById(R.id.editText_billNumber);
        amount = (EditText) findViewById(R.id.editText_billAmount);
        result = (TextView) findViewById(R.id.textView_billResult);
        historyList = (ListView) findViewById(R.id.listView_billHistory);

        historyAdapter = new ArrayAdapter<String>(this, R.layout.item_row, R.id.rowText,
                new ArrayList<String>());
        historyList.setAdapter(historyAdapter);

        Button pay = (Button) findViewById(R.id.button_payBill);
        pay.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                doPayBill();
            }
        });

        Button refresh = (Button) findViewById(R.id.button_refreshBills);
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                loadHistory();
            }
        });

        if (!requireSession()) {
            return;
        }

        loadCategories();
        loadPayerAccounts();
        loadHistory();
    }

    /* ==================================================================== dropdowns */

    private void loadCategories() {
        apiPost("/getbillcategories", authParams(), new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    RaspEvent.error("BillPaymentActivity", uname, opId, "categories rejected");
                    return;
                }
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("categories");
                    List<String> categories = new ArrayList<String>();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            categories.add(arr.getString(i));
                        }
                    }
                    ArrayAdapter<String> a = new ArrayAdapter<String>(BillPaymentActivity.this,
                            android.R.layout.simple_spinner_item, categories);
                    a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
                    categorySpinner.setAdapter(a);
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("BillPaymentActivity", uname, opId,
                            "categories parse: " + e.getMessage());
                }
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("BillPaymentActivity", uname, opId, "categories transport " + message);
            }
        });
    }

    private void loadPayerAccounts() {
        apiPost("/getmyaccounts", authParams(), new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    RaspEvent.error("BillPaymentActivity", uname, opId, "accounts rejected");
                    return;
                }
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("accounts");
                    payerAccounts.clear();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject a = arr.getJSONObject(i);
                            payerAccounts.add(a.getString("account_number"));
                        }
                    }
                    ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                            BillPaymentActivity.this, android.R.layout.simple_spinner_item,
                            payerAccounts);
                    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
                    accountSpinner.setAdapter(adapter);
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("BillPaymentActivity", uname, opId,
                            "accounts parse: " + e.getMessage());
                }
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("BillPaymentActivity", uname, opId, "accounts transport " + message);
            }
        });
    }

    /* ====================================================================== payment */

    /* ==================================================================================
     *  VULNERABILITY ID : RASP-VULN-004
     *  FEATURE          : 4 - Bill Payment
     *  TYPE             : CWE-20 Improper Input Validation
     *  COMPONENT        : BillPaymentActivity.doPayBill()  (client)
     *                     AndroLabServer/app.py :: paybill()  (server)
     *  EXPECTED GOOD    : the client rejects a bill number that is not 6-20 digits and an
     *                     amount that is not a positive number within the payer balance, and
     *                     the server repeats those checks independently before recording
     *                     anything.
     *  ACTUAL BEHAVIOUR : no check of any kind is performed. `bill_number` may be empty,
     *                     contain SQL/shell metacharacters or be 400 characters long and is
     *                     forwarded verbatim; `amount` may be negative, decimal, empty or
     *                     non numeric. The request is sent anyway and the server answers
     *                     "Bill Payment Successful", so a malformed payment is stored as a
     *                     legitimate one.
     *  RUNTIME EVENTS   : BILL_PAYMENT with result=success and a detail that carries
     *                     amount="<raw text>", amount_numeric=false and bill_len=<n>, which
     *                     is the observable signature of the attack.
     *  REPRODUCE        : log in -> Bill Payment, then either
     *                       a) type   '  OR  1=1--   into "Bill / consumer number" and
     *                          1000 into the amount and press "Pay Bill"
     *                       b) type   -1  into the amount and press "Pay Bill"
     *                     In both cases the screen reports a successful payment and the row
     *                     shows up in the payment history.
     *  SAFETY           : the value is only ever bound as a parameter of an INSERT on the
     *                     server, it is never concatenated into SQL or passed to a shell, so
     *                     this cannot execute code and cannot destroy data. A non positive
     *                     amount does not move any balance, so the fixture stays consistent.
     * ================================================================================== */
    private void doPayBill() {
        Object cat = categorySpinner.getSelectedItem();
        final String category = cat == null ? "" : String.valueOf(cat);
        Object acc = accountSpinner.getSelectedItem();
        final String payerAccount = acc == null ? "" : String.valueOf(acc);

        //  Intentionally NOT validated - see the block comment above.
        final String rawBillNumber = billNumber.getText().toString();
        final String rawAmount = amount.getText().toString();

        RaspEvent.ok(RaspEvent.BILL_PAYMENT, "BillPaymentActivity", uname, opId,
                "stage=submit category=" + category
                        + " account=" + payerAccount
                        + " bill_len=" + rawBillNumber.length()
                        + " amount=\"" + rawAmount + "\""
                        + " amount_numeric=" + isNumeric(rawAmount));

        List<NameValuePair> params = authParams();
        addParam(params, "category", category);
        addParam(params, "bill_number", rawBillNumber);
        addParam(params, "amount", rawAmount);
        addParam(params, "payer_account", payerAccount);

        apiPost("/paybill", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                boolean ok = body != null && body.indexOf("Bill Payment Successful") != -1;
                String reference = "";
                if (ok) {
                    try {
                        reference = new JSONObject(body).optString("reference", "");
                    } catch (JSONException e) {
                        // TODO Auto-generated catch block
                        reference = "";
                    }
                }
                RaspEvent.log(RaspEvent.BILL_PAYMENT, "BillPaymentActivity", uname,
                        ok ? RaspEvent.RESULT_SUCCESS : RaspEvent.RESULT_FAILURE, opId,
                        "stage=result category=" + category
                                + " amount=\"" + rawAmount + "\""
                                + " amount_numeric=" + isNumeric(rawAmount)
                                + " bill_len=" + rawBillNumber.length()
                                + " reference=" + reference);
                if (ok) {
                    result.setText("Payment successful. Reference " + reference);
                    Toasteroid.show(BillPaymentActivity.this, "Bill payment successful",
                            Toasteroid.STYLES.SUCCESS, Toasteroid.LENGTH_SHORT);
                } else {
                    result.setText("Payment could not be completed");
                    Toasteroid.show(BillPaymentActivity.this, "Bill payment failed",
                            Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_SHORT);
                }
                loadHistory();
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.fail(RaspEvent.BILL_PAYMENT, "BillPaymentActivity", uname, opId,
                        "stage=result transport=" + message);
                result.setText("Server not reachable");
            }
        });
    }

    /* ====================================================================== history */

    private void loadHistory() {
        apiPost("/getbillhistory", authParams(), new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    RaspEvent.fail(RaspEvent.BILL_PAYMENT_HISTORY_VIEW, "BillPaymentActivity",
                            uname, opId, "server rejected the request");
                    return;
                }
                int count = 0;
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("payments");
                    List<String> rows = new ArrayList<String>();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject p = arr.getJSONObject(i);
                            rows.add(p.optString("date") + " | " + p.optString("category")
                                    + " | " + p.optString("amount")
                                    + " | bill " + p.optString("bill_number")
                                    + " | " + p.optString("status"));
                            count++;
                        }
                    }
                    historyAdapter.clear();
                    historyAdapter.addAll(rows);
                    historyAdapter.notifyDataSetChanged();
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("BillPaymentActivity", uname, opId,
                            "history parse: " + e.getMessage());
                }
                RaspEvent.ok(RaspEvent.BILL_PAYMENT_HISTORY_VIEW, "BillPaymentActivity",
                        uname, opId, "rows=" + count);
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("BillPaymentActivity", uname, opId, "history transport " + message);
            }
        });
    }

    /** @return true only for a plain, non negative integer - reported to the event stream. */
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
