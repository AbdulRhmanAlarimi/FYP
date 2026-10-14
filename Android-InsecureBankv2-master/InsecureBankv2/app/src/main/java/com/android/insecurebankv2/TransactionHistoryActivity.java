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

import org.apache.http.NameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/*
 * ===========================================================================================
 *  FEATURE 2 - TRANSACTION HISTORY
 *
 *  Normal workflow : LOGIN -> TRANSACTION HISTORY -> SYNC -> FILTER -> VIEW TRANSACTION
 *
 *  "Sync" pulls POST /gettransactions and refreshes the local cache
 *  (TransactionCacheDb / insecurebank_cache.db). "Show All" is a safe, parameterised
 *  listing. "Search" runs the keyword filter, which is the single intentionally
 *  vulnerable statement of the whole application - RASP-VULN-002, implemented in
 *  TransactionCacheDb.search().
 *
 *  The screen can also be opened directly with the keyword pre-filled:
 *      adb shell am start -n com.android.insecurebankv2/.TransactionHistoryActivity \
 *          --es uname dinesh --es preset_keyword "' OR '1'='1"
 *      NOTE: this activity is NOT exported, so `am start` on it is refused by the
 *      system with a SecurityException. The extra only applies to an in-app launch.
 *      To script the payload from adb, remember that `input text` drops the quote
 *      character - send each ' with `input keyevent 75` instead.
 * ===========================================================================================
 */
public class TransactionHistoryActivity extends RaspBankActivity {

    private static final String[] TYPE_FILTERS =
            {"ALL", "TRANSFER", "DEPOSIT", "BILL_PAYMENT"};

    private TransactionCacheDb db;
    private ArrayAdapter<String> adapter;
    private ListView list;
    private TextView summary;
    private EditText search;
    private Spinner typeSpinner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_transaction_history);

        db = new TransactionCacheDb(this);
        list = (ListView) findViewById(R.id.listView_transactions);
        summary = (TextView) findViewById(R.id.textView_summary);
        search = (EditText) findViewById(R.id.editText_search);
        typeSpinner = (Spinner) findViewById(R.id.spinner_type);

        ArrayAdapter<String> types = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, TYPE_FILTERS);
        types.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        typeSpinner.setAdapter(types);

        adapter = new ArrayAdapter<String>(this, R.layout.item_row, R.id.rowText,
                new ArrayList<String>());
        list.setAdapter(adapter);

        Button doSearch = (Button) findViewById(R.id.button_search);
        doSearch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                searchTransactions();
            }
        });

        Button showAll = (Button) findViewById(R.id.button_showAll);
        showAll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                showAll();
            }
        });

        Button sync = (Button) findViewById(R.id.button_sync);
        sync.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // TODO Auto-generated method stub
                sync();
            }
        });

        if (!requireSession()) {
            return;
        }

        list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                // TODO Auto-generated method stub
                Object item = parent.getItemAtPosition(position);
                RaspEvent.ok(RaspEvent.TRANSACTION_HISTORY_VIEW, "TransactionHistoryActivity",
                        uname, opId, "action=open_row detail=" + item);
            }
        });

        // An externally supplied keyword is honoured. This is the entry point used by the
        // RASP-VULN-002 reproduction script; a normal user never sees it.
        String preset = getIntent() == null ? null : getIntent().getStringExtra("preset_keyword");
        if (preset != null) {
            search.setText(preset);
        }

        showAll();
        sync();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (db != null) {
            db.close();
        }
    }

    /* ========================================================================== sync */

    private void sync() {
        List<NameValuePair> params = authParams();
        apiPost("/gettransactions", params, new ApiCallback() {

            @Override
            public void onResult(String body) {
                if (bodyOrNull(body, "Correct Credentials") == null) {
                    RaspEvent.error("TransactionHistoryActivity", uname, opId,
                            "sync rejected by server");
                    return;
                }
                int cached = 0;
                try {
                    JSONArray arr = new JSONObject(body).optJSONArray("transactions");
                    List<Object[]> rows = new ArrayList<Object[]>();
                    if (arr != null) {
                        for (int i = 0; i < arr.length(); i++) {
                            JSONObject t = arr.getJSONObject(i);
                            rows.add(new Object[]{
                                    t.optString("reference"),
                                    t.optString("account_number"),
                                    t.optString("type"),
                                    t.optString("direction"),
                                    t.optInt("amount"),
                                    t.optString("counterparty"),
                                    t.optString("date")});
                        }
                    }
                    db.replaceFor(uname, rows);
                    cached = rows.size();
                } catch (JSONException e) {
                    // TODO Auto-generated catch block
                    RaspEvent.error("TransactionHistoryActivity", uname, opId,
                            "sync parse: " + e.getMessage());
                }
                RaspEvent.ok(RaspEvent.TRANSACTION_HISTORY_VIEW, "TransactionHistoryActivity",
                        uname, opId, "action=sync cached=" + cached);
                showAll();
            }

            @Override
            public void onError(String message) {
                // TODO Auto-generated method stub
                RaspEvent.error("TransactionHistoryActivity", uname, opId,
                        "sync transport " + message);
            }
        });
    }

    /* ========================================================================== views */

    private void showAll() {
        List<String> rows = db.queryRecent(uname, 200);
        render(rows);
        RaspEvent.ok(RaspEvent.TRANSACTION_HISTORY_VIEW, "TransactionHistoryActivity",
                uname, opId, "action=show_all rows=" + rows.size());
    }

    /**
     * Keyword filter. Reaches TransactionCacheDb.search() which is RASP-VULN-002.
     */
    private void searchTransactions() {
        String keyword = search.getText().toString();
        Object selected = typeSpinner.getSelectedItem();
        String type = selected == null ? "ALL" : String.valueOf(selected);

        RaspEvent.ok(RaspEvent.TRANSACTION_SEARCH, "TransactionHistoryActivity", uname,
                opId, "keyword_len=" + keyword.length() + " type=" + type
                + " keyword=[" + keyword + "]");

        List<String> rows = db.search(uname, keyword, type);
        render(rows);

        RaspEvent.log(RaspEvent.TRANSACTION_SEARCH_RESULT, "TransactionHistoryActivity",
                uname, RaspEvent.RESULT_SUCCESS, opId,
                "rows=" + rows.size() + " type=" + type);
    }

    private void render(List<String> rows) {
        adapter.clear();
        adapter.addAll(rows);
        adapter.notifyDataSetChanged();
        summary.setText(rows.isEmpty()
                ? "No transactions to show"
                : rows.size() + " transaction(s), cached total " + db.countFor(uname));
    }
}
