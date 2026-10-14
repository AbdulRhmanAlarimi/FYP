package com.android.insecurebankv2;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.marcohc.toasteroid.Toasteroid;

import org.apache.http.NameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/*
 * ===========================================================================================
 *  FEATURE 3 - BENEFICIARY MANAGEMENT
 *
 *  Normal workflow : LOGIN -> BENEFICIARIES -> ADD BENEFICIARY -> TRANSFER
 *  The same screen doubles as the beneficiary picker for the transfer screen, see
 *  EXTRA_SELECT_MODE below.
 *
 *  Backend       : /getbeneficiaries , /addbeneficiary , /deletebeneficiary
 *                  Every one of them authenticates the caller, and /deletebeneficiary also
 *                  verifies that the row belongs to that caller. The only defect of this
 *                  feature is the client side component exposure documented on
 *              handleExternalAutofill() below - RASP-VULN-003.
 *
 *  Intents accepted by this activity
 *  ---------------------------------
 *    uname                  account the screen operates on
 *    select_mode    (bool)  picker mode, returns the chosen account to the caller
 *    autofill_bene_name     pre-filled beneficiary name
 *    autofill_bene_account  pre-filled beneficiary account number
 *    autofill_bene_bank     pre-filled beneficiary bank
 * ===========================================================================================
 */
public class BeneficiaryActivity extends RaspBankActivity {

    public static final String EXTRA_UNAME = "uname";
    public static final String EXTRA_SELECT_MODE = "select_mode";
    public static final String EXTRA_SELECTED_ACCOUNT = "selected_beneficiary_account";
    public static final String EXTRA_SELECTED_NAME = "selected_beneficiary_name";
    /** pre-filled form values; only ever supplied by an external caller */
    public static final String EXTRA_AUTOFILL_NAME = "autofill_bene_name";
    public static final String EXTRA_AUTOFILL_ACCOUNT = "autofill_bene_account";
    public static final String EXTRA_AUTOFILL_BANK = "autofill_bene_bank";

    private static final String[] ACCOUNT_TYPES = {"Savings", "Current", "Salary"};

    private EditText name;
    private EditText account;
    private EditText bank;
    private Spinner typeSpinner;
    private ListView list;
    private BeneficiaryAdapter adapter;
    private boolean selectMode = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_beneficiary);

        name = (EditText) findViewById(R.id.editText_beneName);
        account = (EditText) findViewById(R.id.editText_beneAccount);
        bank = (EditText) findViewById(R.id.editText_beneBank);
        typeSpinner = (Spinner) findViewById(R.id.spinner_beneType);
        list = (ListView) findViewById(R.id.listView_beneficiaries);

        ArrayAdapter<String> types = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, ACCOUNT_TYPES);
        types.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        typeSpinner.setAdapter(types);

        selectMode = getIntent() != null
                && getIntent().getBooleanExtra(EXTRA_SELECT_MODE, false);

        adapter = new BeneficiaryAdapter();
        list.setAdapter(adapter);

        Button add = (Button) findViewById(R.id.button_addBeneficiary);
        add.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                addBeneficiary("form");
            }
        });

        Button refresh = (Button) findViewById(R.id.button_refreshBeneficiaries);
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                loadBeneficiaries();
            }
        });

        if (getIntent() != null) {
            String preName = getIntent().getStringExtra(EXTRA_AUTOFILL_NAME);
            String preAccount = getIntent().getStringExtra(EXTRA_AUTOFILL_ACCOUNT);
            String preBank = getIntent().getStringExtra(EXTRA_AUTOFILL_BANK);
            if (preName != null) {
                name.setText(preName);
            }
            if (preAccount != null) {
                account.setText(preAccount);
            }
            if (preBank != null) {
                bank.setText(preBank);
            }
        }

        if (!requireSession()) {
            return;
        }

        if (selectMode) {
            setTitle("Select Beneficiary");
        }

        loadBeneficiaries();
        handleExternalAutofill();
    }

    /* ================================================================== list / load */

    private void loadBeneficiaries() {
        List<NameValuePair> params = authParams();
        apiPost("/getbeneficiaries", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    track(RaspEvent.BENEFICIARY_VIEW, false, "server rejected the request");
                    return;
                }
                int count = 0;
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("beneficiaries");
                    adapter.rows.clear();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject b = arr.getJSONObject(i);
                            adapter.rows.add(new String[]{
                                    String.valueOf(b.optInt("id")),
                                    b.optString("name"),
                                    b.optString("account_number"),
                                    b.optString("bank_name")});
                            count++;
                        }
                    }
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("BeneficiaryActivity", uname, opId,
                            "beneficiary parse: " + e.getMessage());
                }
                adapter.notifyDataSetChanged();
                RaspEvent.ok(RaspEvent.BENEFICIARY_VIEW, "BeneficiaryActivity", uname,
                        opId, "rows=" + count + " select_mode=" + selectMode);
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("BeneficiaryActivity", uname, opId,
                        "beneficiary transport " + message);
            }
        });
    }

    /* ============================================================================= add */

    /**
     * @param source "form" for a tap on the Add button, "external_intent" when the screen
     *               was opened by another application (RASP-VULN-003).
     */
    private void addBeneficiary(final String source) {
        final String beneName = name.getText().toString().trim();
        final String beneAccount = account.getText().toString().trim();
        final String beneBank = bank.getText().toString().trim();
        Object selected = typeSpinner.getSelectedItem();
        final String beneType = selected == null ? "Savings" : String.valueOf(selected);

        if (beneName.length() == 0 || beneAccount.length() == 0) {
            RaspEvent.fail(RaspEvent.BENEFICIARY_ADD, "BeneficiaryActivity", uname, opId,
                    "source=" + source + " reason=missing_fields");
            Toasteroid.show(this, "Name and account number are required",
                    Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_SHORT);
            return;
        }

        List<NameValuePair> params = authParams();
        addParam(params, "name", beneName);
        addParam(params, "account_number", beneAccount);
        addParam(params, "bank_name", beneBank);
        addParam(params, "account_type", beneType);

        apiPost("/addbeneficiary", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                boolean ok = body != null && body.indexOf("Beneficiary Added") != -1;
                RaspEvent.log(RaspEvent.BENEFICIARY_ADD, "BeneficiaryActivity", uname,
                        ok ? RaspEvent.RESULT_SUCCESS : RaspEvent.RESULT_FAILURE, opId,
                        "source=" + source + " account=" + beneAccount
                                + " type=" + beneType);
                if (ok) {
                    if (!"external_intent".equals(source)) {
                        Toasteroid.show(BeneficiaryActivity.this, "Beneficiary added",
                                Toasteroid.STYLES.SUCCESS, Toasteroid.LENGTH_SHORT);
                    }
                    name.setText("");
                    account.setText("");
                    bank.setText("");
                } else {
                    if (!"external_intent".equals(source)) {
                        Toasteroid.show(BeneficiaryActivity.this, "Could not add beneficiary",
                                Toasteroid.STYLES.ERROR, Toasteroid.LENGTH_SHORT);
                    }
                }
                loadBeneficiaries();
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.fail(RaspEvent.BENEFICIARY_ADD, "BeneficiaryActivity", uname, opId,
                        "source=" + source + " transport=" + message);
            }
        });
    }

    /* ============================================================================= del */

    private void deleteBeneficiary(final String id) {
        List<NameValuePair> params = authParams();
        addParam(params, "id", id);
        apiPost("/deletebeneficiary", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                boolean ok = body != null && body.indexOf("Beneficiary Deleted") != -1;
                RaspEvent.log(RaspEvent.BENEFICIARY_DELETE, "BeneficiaryActivity", uname,
                        ok ? RaspEvent.RESULT_SUCCESS : RaspEvent.RESULT_FAILURE, opId,
                        "id=" + id);
                toast(ok ? "Beneficiary deleted" : "Could not delete beneficiary", ok);
                loadBeneficiaries();
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.fail(RaspEvent.BENEFICIARY_DELETE, "BeneficiaryActivity", uname,
                        opId, "id=" + id + " transport=" + message);
            }
        });
    }

    /* =================================================================== select mode */

    private void returnSelection(String beneficiaryName, String beneficiaryAccount) {
        RaspEvent.ok(RaspEvent.BENEFICIARY_SELECT, "BeneficiaryActivity", uname, opId,
                "account=" + beneficiaryAccount);
        Intent result = new Intent();
        result.putExtra(EXTRA_SELECTED_ACCOUNT, beneficiaryAccount);
        result.putExtra(EXTRA_SELECTED_NAME, beneficiaryName);
        setResult(RESULT_OK, result);
        finish();
    }

    /* ==================================================================================
     *  VULNERABILITY ID : RASP-VULN-003
     *  FEATURE          : 3 - Beneficiary Management
     *  TYPE             : CWE-926 Improper Export of Android Application Components
     *                     combined with CWE-862 Missing Authorization
     *  COMPONENT        : BeneficiaryActivity, declared in AndroidManifest.xml with
     *                       android:exported="true"
     *                       and an <intent-filter> (action com.android.insecurebankv2.BENEFICIARY)
     *                       plus this method.
     *  EXPECTED GOOD    : android:exported="false" and no intent filter, or the component
     *                     guarded by a signature-level permission, plus a check that the
     *                     intent really came from inside the application before acting on
     *                     the data it carries.
     *  ACTUAL BEHAVIOUR : the activity is reachable by any application on the device and by
     *                     `adb shell am start`. It performs its privileged action purely on
     *                     the strength of the extras it was given - the target `uname` and
     *                     the pre-filled beneficiary fields - with no permission check, no
     *                     caller verification and no user confirmation.
     *  RUNTIME EVENTS   : BENEFICIARY_ADD with detail "source=external_intent", preceded by
     *                     BENEFICIARY_VIEW, and the normal SERVER_REQUEST/SERVER_RESPONSE
     *                     pair. The success/failure flag is identical to an in-app add,
     *                     which is exactly what makes the anomaly detectable.
     *  REPRODUCE        : while `dinesh` is logged in on the device, from any other app or
     *                     from a shell:
     *                       adb shell am start -n com.android.insecurebankv2/.BeneficiaryActivity \
     *                           --es uname dinesh \
     *                           --es autofill_bene_name "External Payee" \
     *                           --es autofill_bene_account 111122223333
     *                     -> "External Payee" now appears in dinesh's beneficiary list,
     *                        the screen is never shown to the user and no permission was
     *                        required. Opening the same activity without the autofill
     *                        extras also discloses the payee names and account numbers to
     *                        whatever application launched it.
     *  BLAST RADIUS     : limited to the beneficiary list of the account that is already
     *                     logged in on the device. No data is deleted, no money moves, and
     *                     the normal in-app workflow is completely unaffected because the
     *                     trigger only exists in the intent extras.
     * ================================================================================== */
    private void handleExternalAutofill() {
        if (getIntent() == null) {
            return;
        }
        String preName = getIntent().getStringExtra(EXTRA_AUTOFILL_NAME);
        String preAccount = getIntent().getStringExtra(EXTRA_AUTOFILL_ACCOUNT);
        if (preName == null && preAccount == null) {
            return;   // ordinary in-app launch, nothing to do
        }
        RaspEvent.ok(RaspEvent.NAVIGATE, "BeneficiaryActivity", uname, opId,
                "source=external_intent autofill=1 select_mode=" + selectMode);
        addBeneficiary("external_intent");
    }

    /* ========================================================================= adapter */

    private class BeneficiaryAdapter extends BaseAdapter {

        final List<String[]> rows = new ArrayList<String[]>();

        @Override
        public int getCount() {
            return rows.size();
        }

        @Override
        public Object getItem(int position) {
            return rows.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View view = convertView;
            if (view == null) {
                view = LayoutInflater.from(BeneficiaryActivity.this)
                        .inflate(R.layout.item_beneficiary, parent, false);
            }
            final String[] row = rows.get(position);

            TextView nameView = (TextView) view.findViewById(R.id.beneficiaryName);
            TextView accountView = (TextView) view.findViewById(R.id.beneficiaryAccount);
            Button delete = (Button) view.findViewById(R.id.button_deleteBeneficiary);

            nameView.setText(row[1]);
            accountView.setText(row[2] + (row[3].length() > 0 ? "  -  " + row[3] : ""));

            delete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    // TODO Auto-generated method stub
                    deleteBeneficiary(row[0]);
                }
            });

            if (selectMode) {
                delete.setVisibility(View.GONE);
            } else {
                delete.setVisibility(View.VISIBLE);
            }

            view.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    // TODO Auto-generated method stub
                    if (selectMode) {
                        returnSelection(row[1], row[2]);
                    } else {
                        Toast.makeText(BeneficiaryActivity.this,
                                row[1] + " - " + row[2], Toast.LENGTH_SHORT).show();
                    }
                }
            });
            return view;
        }
    }
}
