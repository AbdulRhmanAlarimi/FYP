package com.android.insecurebankv2;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

/**
 * On-device cache of the transaction rows returned by POST /gettransactions.
 *
 * It lives in its own database file (insecurebank_cache.db) so that it cannot interfere
 * with the pre-existing mydb.db that backs TrackUserContentProvider. The original content
 * provider, its schema and its exported URI surface are left completely untouched.
 *
 * The "list everything" path (queryRecent) is properly parameterised. The keyword search
 * path (search) is NOT, on purpose - see the block comment on that method.
 */
public class TransactionCacheDb extends SQLiteOpenHelper {

    public static final String DATABASE_NAME = "insecurebank_cache.db";
    public static final int DATABASE_VERSION = 1;

    public static final String TABLE = "transaction_cache";

    public static final String COL_ID = "_id";
    public static final String COL_OWNER = "owner";
    public static final String COL_REFERENCE = "reference";
    public static final String COL_ACCOUNT = "account_number";
    public static final String COL_TYPE = "type";
    public static final String COL_DIRECTION = "direction";
    public static final String COL_AMOUNT = "amount";
    public static final String COL_COUNTERPARTY = "counterparty";
    public static final String COL_DATE = "txn_date";

    private static final String CREATE =
            "CREATE TABLE " + TABLE + " ("
                    + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + COL_OWNER + " TEXT NOT NULL, "
                    + COL_REFERENCE + " TEXT, "
                    + COL_ACCOUNT + " TEXT, "
                    + COL_TYPE + " TEXT, "
                    + COL_DIRECTION + " TEXT, "
                    + COL_AMOUNT + " INTEGER, "
                    + COL_COUNTERPARTY + " TEXT, "
                    + COL_DATE + " TEXT);";

    public TransactionCacheDb(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(CREATE);
        db.execSQL("CREATE INDEX idx_cache_owner ON " + TABLE + " (" + COL_OWNER + ");");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // The cache is disposable, dropping it is the cheapest correct migration.
        db.execSQL("DROP TABLE IF EXISTS " + TABLE);
        onCreate(db);
    }

    /* =================================================================== write side */

    /**
     * Replaces the cached rows of one user with the freshly synchronised list.
     */
    public void replaceFor(String owner, List<Object[]> rows) {
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            db.delete(TABLE, COL_OWNER + " = ?", new String[]{owner});
            for (Object[] row : rows) {
                ContentValues v = new ContentValues();
                v.put(COL_OWNER, owner);
                v.put(COL_REFERENCE, str(row[0]));
                v.put(COL_ACCOUNT, str(row[1]));
                v.put(COL_TYPE, str(row[2]));
                v.put(COL_DIRECTION, str(row[3]));
                v.put(COL_AMOUNT, row[4] instanceof Number ? ((Number) row[4]).intValue() : 0);
                v.put(COL_COUNTERPARTY, str(row[5]));
                v.put(COL_DATE, str(row[6]));
                db.insert(TABLE, null, v);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    /* =================================================================== read side */

    /**
     * SAFE - the default "show me my history" listing. Fully parameterised.
     */
    public List<String> queryRecent(String owner, int limit) {
        List<String> out = new ArrayList<String>();
        Cursor c = null;
        try {
            c = getReadableDatabase().rawQuery(
                    "SELECT * FROM " + TABLE + " WHERE " + COL_OWNER + " = ?"
                            + " ORDER BY " + COL_ID + " DESC LIMIT " + Math.max(1, limit),
                    new String[]{owner});
            while (c.moveToNext()) {
                out.add(format(c));
            }
        } catch (SQLiteException e) {
            RaspEvent.error("TransactionCacheDb", owner, RaspEvent.newOpId(),
                    "queryRecent failed: " + e.getMessage());
        } finally {
            close(c);
        }
        return out;
    }

    public int countFor(String owner) {
        Cursor c = null;
        try {
            c = getReadableDatabase().rawQuery(
                    "SELECT COUNT(*) FROM " + TABLE + " WHERE " + COL_OWNER + " = ?",
                    new String[]{owner});
            return c.moveToFirst() ? c.getInt(0) : 0;
        } catch (SQLiteException e) {
            return 0;
        } finally {
            close(c);
        }
    }

    /* ==================================================================================
     *  VULNERABILITY ID : RASP-VULN-002
     *  FEATURE          : 2 - Transaction History  (keyword search)
     *  TYPE             : CWE-89 Improper Neutralization of Special Elements used in an
     *                     SQL Command ('SQL Injection'), LOCAL (on-device SQLite) variant
     *  COMPONENT        : this method, and its single caller
     *                     TransactionHistoryActivity.searchTransactions()
     *  EXPECTED GOOD    : `db.rawQuery(sql, new String[]{owner, "%" + keyword + "%", ...})`
     *                     so that the keyword can never change the shape of the statement.
     *  ACTUAL BEHAVIOUR : the keyword is pasted into the statement with `+` string
     *                     concatenation, so it can inject arbitrary SQL predicates.
     *
     *  REPRODUCE (local test environment)
     *  ----------------------------------
     *    1. log in, open "Transaction History", press "Sync"
     *    2. type into the search box:            '  OR  '1'='1
     *    3. press "Search"
     *       -> every cached row is returned even though no row contains the literal text.
     *    4. type:   x') UNION SELECT reference,account_number,type,direction,
     *                    amount,counterparty,txn_date FROM transaction_cache --
     *       -> the UNION arm is executed by the local SQLite engine. It has to start
     *          with ')' because a UNION cannot sit inside the ( ... ) LIKE group.
     *          7 columns, one per column of the SELECT above.
     *    5. type:   '  OR  1=0 --          -> the list comes back empty.
     *
     *  BLAST RADIUS
     *  ------------
     *  The statement only ever runs against insecurebank_cache.db, a throw-away local
     *  cache owned by this application. It cannot reach the backend, cannot touch
     *  mydb.db (the TrackUserContentProvider database) and cannot execute code. The
     *  clearest payloads are read-only, and a malformed payload is caught and reported
     *  instead of crashing - see the catch block below.
     *
     *  This is the ONLY unparameterised statement in the application. Every other query
     *  in the new code base uses selection arguments.
     * ================================================================================== */
    public List<String> search(String owner, String keyword, String type) {
        List<String> out = new ArrayList<String>();
        Cursor c = null;
        try {
            //  ---- VULNERABLE: `keyword` is concatenated into the statement ----
            String columns = COL_REFERENCE + ", " + COL_ACCOUNT + ", " + COL_TYPE
                    + ", " + COL_DIRECTION + ", " + COL_AMOUNT + ", " + COL_COUNTERPARTY
                    + ", " + COL_DATE;
            String sql = "SELECT " + columns + " FROM " + TABLE
                    + " WHERE " + COL_OWNER + " = ?"
                    + " AND (" + COL_COUNTERPARTY + " LIKE '%" + keyword + "%'"
                    + "   OR " + COL_REFERENCE + " LIKE '%" + keyword + "%'"
                    + "   OR " + COL_TYPE + " LIKE '%" + keyword + "%'"
                    + "   OR " + COL_ACCOUNT + " LIKE '%" + keyword + "%')";
            if (type != null && type.length() > 0 && !"ALL".equals(type)) {
                sql = sql + " AND " + COL_TYPE + " = '" + type + "'";
            }
            sql = sql + " ORDER BY " + COL_ID + " DESC LIMIT 200";
            //  -------------------------------------------------------------------------

            c = getReadableDatabase().rawQuery(sql, new String[]{owner});
            while (c.moveToNext()) {
                out.add(format(c));
            }
        } catch (SQLiteException e) {
            // Keeps the application alive when the payload is not valid SQL.
            RaspEvent.error("TransactionCacheDb", owner, RaspEvent.newOpId(),
                    "search rejected: " + e.getMessage());
            out.add("Search could not be completed.");
        } finally {
            close(c);
        }
        return out;
    }

    /* ======================================================================== utils */

    private static String format(Cursor c) {
        return c.getString(c.getColumnIndexOrThrow(COL_DATE)) + " | "
                + c.getString(c.getColumnIndexOrThrow(COL_TYPE)) + " "
                + c.getString(c.getColumnIndexOrThrow(COL_DIRECTION)) + " | "
                + c.getString(c.getColumnIndexOrThrow(COL_AMOUNT)) + " | "
                + c.getString(c.getColumnIndexOrThrow(COL_ACCOUNT)) + " | "
                + c.getString(c.getColumnIndexOrThrow(COL_COUNTERPARTY));
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static void close(Cursor c) {
        if (c != null) {
            c.close();
        }
    }
}
