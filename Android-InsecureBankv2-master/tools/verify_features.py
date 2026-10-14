#!/usr/bin/env python3
"""
End-to-end verification of the six added features.

Replays, request for request, exactly what each Android screen sends (same endpoint,
same form field names, same values a user would type), then proves that each of the six
intentional vulnerabilities actually triggers and that the benign workflows stay intact.
"""
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("IB_BASE", "http://127.0.0.1:8888")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "AndroLabServer", "mydb.db")
CACHE = "/tmp/opencode/insecurebank_cache.db"

USER = "dinesh"
PASSWORD = "Dinesh@123$"
OTHER_ACCOUNT = "555555555"   # jack's account, not owned by dinesh

#  Every account this script signs up is created under this prefix and removed again by
#  reset_backend(), so the fixture is left exactly as it was seeded.
TEST_USER_PREFIX = "rasptest"

passed, failed = 0, 0


def post(endpoint, **fields):
    fields.setdefault("username", USER)
    fields.setdefault("password", PASSWORD)
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(BASE + "/" + endpoint, data=data)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def raw_post(endpoint, **fields):
    """POST without injecting the credentials of the seeded account.

    Signup is the one endpoint that must not be called through post(): there is no
    authenticated caller yet and username/password are the payload, not the session.
    """
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(BASE + "/" + endpoint, data=data)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def check(name, condition, extra=""):
    global passed, failed
    if condition:
        passed += 1
        print("  PASS  %-58s %s" % (name, extra))
    else:
        failed += 1
        print("  FAIL  %-58s %s" % (name, extra))


def reset_backend():
    con = sqlite3.connect(DB)
    con.executescript("""
        DELETE FROM transactions;
        DELETE FROM beneficiaries;
        DELETE FROM bill_payments;
        DELETE FROM accounts WHERE user LIKE 'rasptest%';
        DELETE FROM users   WHERE username LIKE 'rasptest%';
        UPDATE accounts SET balance = CASE account_number
            WHEN 123456789 THEN 99999 WHEN 888888888 THEN 99597
            WHEN 666666666 THEN 100288 WHEN 987654321 THEN 99999
            WHEN 999999999 THEN 99539 WHEN 555555555 THEN 100459 END;
    """)
    con.commit()
    con.close()


def balance(account):
    con = sqlite3.connect(DB)
    row = con.execute("SELECT balance FROM accounts WHERE account_number=?", (account,)).fetchone()
    con.close()
    return row[0] if row else None


def accounts_of(user):
    con = sqlite3.connect(DB)
    rows = con.execute("SELECT account_number, type, balance FROM accounts WHERE user=?",
                       (user,)).fetchall()
    con.close()
    return rows


# ==========================================================================================
# Start from the seeded fixture so a crashed earlier run cannot skew the counts.
reset_backend()

print("\n[0] pre-existing routes still behave exactly as before (regression check)")
r = post("login")
check("POST /login", r.get("message") == "Correct Credentials")
r = post("login", password="wrong")
check("POST /login wrong password", r.get("message") == "Wrong Password")
r = post("getaccounts")
check("POST /getaccounts", r.get("message", "").startswith("Correct"), "from=%s to=%s" % (r.get("from"), r.get("to")))
r = post("dotransfer", from_acc="123456789", to_acc="666666666", amount="1000")
check("POST /dotransfer", r.get("message") == "Success")
r = post("dotransfer", from_acc="123456789", to_acc="666666666", amount="1000")
check("POST /dotransfer again", r.get("message") == "Success")

# ==========================================================================================
print("\n[1] Account Details  -  benign")
r = post("getaccountdetails")
check("getaccountdetails authenticates", r.get("message") == "Correct Credentials")
check("holder name returned", r.get("holder_name") == "dinesh shetty", r.get("holder_name"))
check("primary account + type + balance",
      r.get("account_number") and r.get("account_type") and r.get("balance") is not None,
      "%s / %s / %s" % (r.get("account_number"), r.get("account_type"), r.get("balance")))
check("all own accounts listed", len(r.get("accounts", [])) == 3, str(len(r.get("accounts", []))))
r = post("getaccountdetails", password="wrong")
check("getaccountdetails rejects bad credentials", r.get("message") == "Wrong Credentials")

# ==========================================================================================
print("\n[2] Transaction History  -  benign sync, then the controlled SQL injection")
r = post("gettransactions")
check("gettransactions authenticates", r.get("message") == "Correct Credentials")
transfers = [t for t in r["transactions"] if t["type"] == "TRANSFER"]
check("transfer rows were recorded by /dotransfer", len(transfers) == 2, str(len(transfers)))

# Rebuild the exact local cache table created by TransactionCacheDb.onCreate()
if os.path.exists(CACHE):
    os.remove(CACHE)
con = sqlite3.connect(CACHE)
con.executescript("""
    CREATE TABLE transaction_cache (
        _id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL, reference TEXT, account_number TEXT, type TEXT,
        direction TEXT, amount INTEGER, counterparty TEXT, txn_date TEXT);
    CREATE INDEX idx_cache_owner ON transaction_cache (owner);
    INSERT INTO transaction_cache
        (owner, reference, account_number, type, direction, amount, counterparty, txn_date)
    VALUES ('dinesh','TX1','123456789','TRANSFER','DEBIT',1000,'666666666','2026-09-29 10:00:00'),
           ('dinesh','DEP1','123456789','DEPOSIT','CREDIT',500,'CASH DEPOSIT','2026-09-29 10:05:00'),
           ('dinesh','BILL1','123456789','BILL_PAYMENT','DEBIT',75,'Water','2026-09-29 10:10:00');
""")
con.commit()

# the 7 columns the vulnerable SELECT in TransactionCacheDb.search() projects
COLS = ("reference, account_number, type, direction, amount, counterparty, txn_date")


def cache_search(keyword, type_filter="ALL"):
    """Mirror of TransactionCacheDb.search(), vulnerable line included."""
    sql = ("SELECT " + COLS + " FROM transaction_cache WHERE owner = ?"
           " AND (counterparty LIKE '%" + keyword + "%'"
           "   OR reference LIKE '%" + keyword + "%'"
           "   OR type LIKE '%" + keyword + "%'"
           "   OR account_number LIKE '%" + keyword + "%')")
    if type_filter and type_filter != "ALL":
        sql = sql + " AND type = '" + type_filter + "'"
    sql = sql + " ORDER BY _id DESC LIMIT 200"
    try:
        return [r[0] for r in con.execute(sql, ("dinesh",)).fetchall()], None
    except sqlite3.Error as e:
        return [], str(e)


rows, err = cache_search("DEPOSIT")
check("benign keyword search", rows == ["DEP1"], "refs=%s" % rows)
rows, err = cache_search("666666666")
check("benign account-number search", rows == ["TX1"], "refs=%s" % rows)
rows, err = cache_search("", "BILL_PAYMENT")
check("benign type filter", rows == ["BILL1"], "refs=%s" % rows)
rows, err = cache_search("nothing-matches-this")
check("benign search with no match", rows == [], "refs=%s" % rows)

rows, err = cache_search("'  OR  '1'='1")
check("VULN-002 tautology payload returns everything", rows == ["BILL1", "DEP1", "TX1"],
      "refs=%s" % rows)
rows, err = cache_search("x') UNION SELECT " + COLS + " FROM transaction_cache --")
check("VULN-002 UNION payload executes", len(rows) == 3, "refs=%s" % rows)
rows, err = cache_search("'  OR  1=0 --")
check("VULN-002 can also return nothing", rows == [], "refs=%s" % rows)
rows, err = cache_search("' OR owner='jack")
check("VULN-002 bypasses the owner predicate", rows == ["BILL1", "DEP1", "TX1"],
      "refs=%s" % rows)
rows, err = cache_search("' OR 1=1) UNION ALL SELECT " + COLS + " FROM transaction_cache --")
check("VULN-002 tautology + UNION ALL", len(rows) == 6, "refs=%s" % rows)
rows, err = cache_search("' OR 1=1) UNION SELECT " + COLS + " FROM transaction_cache --")
check("VULN-002 tautology + UNION (de-duplicates)", len(rows) == 3, "refs=%s" % rows)
con.close()

# ==========================================================================================
print("\n[3] Beneficiary Management  -  benign + ownership enforced server side")
r = post("addbeneficiary", name="Rent Landlord", account_number="777777777",
         bank_name="Test Bank", account_type="Savings")
check("addbeneficiary", r.get("message") == "Beneficiary Added", "id=%s" % r.get("id"))
bid = int(r["id"])
r = post("getbeneficiaries")
check("getbeneficiaries lists it", len(r["beneficiaries"]) == 1, str(r["beneficiaries"]))
r = post("deletebeneficiary", id=bid)
check("deletebeneficiary (owner)", r.get("message") == "Beneficiary Deleted")
r = post("deletebeneficiary", id=bid)
check("deletebeneficiary is idempotent-safe", r.get("message") == "Beneficiary not found")
r = post("addbeneficiary", name="", account_number="")
check("addbeneficiary validates empty fields",
      r.get("message") == "Beneficiary name and account number are required")
r = post("getbeneficiaries", username="jack", password="Jack@123$")
check("getbeneficiaries is scoped per user", len(r["beneficiaries"]) == 0, str(r["beneficiaries"]))

# ==========================================================================================
print("\n[4] Bill Payment  -  benign + VULN-004 no validation")
r = post("getbillcategories")
check("getbillcategories", len(r.get("categories", [])) == 6)
before = balance("123456789")
r = post("paybill", category="Water", bill_number="5551234", amount="120",
         payer_account="123456789")
check("benign bill payment succeeds", r.get("message") == "Bill Payment Successful",
      "ref=%s" % r.get("reference"))
check("benign bill payment debits the payer", balance("123456789") == before - 120,
      "%s -> %s" % (before, balance("123456789")))
r = post("getbillhistory")
check("getbillhistory lists it", len(r.get("payments", [])) == 1)

before = balance("123456789")
r = post("paybill", category="Water", bill_number="'  OR  '1'='1", amount="500",
         payer_account="123456789")
check("VULN-004 metacharacter bill number accepted", r.get("message") == "Bill Payment Successful")
check("VULN-004 stored verbatim", r.get("bill_number") == "'  OR  '1'='1", repr(r.get("bill_number")))
check("VULN-004 positive amount still debits", balance("123456789") == before - 500,
      "%s -> %s" % (before, balance("123456789")))

before = balance("123456789")
r = post("paybill", category="Water", bill_number="5551234", amount="-9999",
         payer_account="123456789")
check("VULN-004 negative amount accepted", r.get("message") == "Bill Payment Successful")
check("VULN-004 negative amount does NOT move money", balance("123456789") == before,
      "balance still %s" % balance("123456789"))
r = post("paybill", category="Water", bill_number="", amount="not-a-number",
         payer_account="123456789")
check("VULN-004 empty/non-numeric accepted", r.get("message") == "Bill Payment Successful")

# ==========================================================================================
print("\n[5] Profile Management  -  benign")
r = post("getprofile")
check("getprofile", r.get("full_name") == "dinesh shetty", r.get("full_name"))
check("seeded contact data is fake test data",
      r.get("email", "").endswith(".invalid"), r.get("email"))
r = post("updateprofile", first_name="dinesh", last_name="shetty",
         email="dinesh.test@example.invalid", phone="+1-555-0100", address="12 Test Street")
check("updateprofile", r.get("message") == "Profile Updated")
r = post("getprofile", email="dinesh.test@example.invalid")
check("updateprofile persists email", r.get("email") == "dinesh.test@example.invalid")

# ==========================================================================================
print("\n[6] Deposit Money  -  benign + VULN-006 missing authorization")
own_before = balance("123456789")
other_before = balance(OTHER_ACCOUNT)
r = post("deposit", account_number="123456789", amount="500")
check("benign deposit succeeds", r.get("message") == "Deposit Successful", "ref=%s" % r.get("reference"))
check("benign deposit credits the owner", balance("123456789") == own_before + 500,
      "%s -> %s" % (own_before, balance("123456789")))
check("benign deposit returns the new balance", r.get("balance") == balance("123456789"))

r = post("deposit", account_number=OTHER_ACCOUNT, amount="5000")
check("VULN-006 deposits into ANOTHER user's account", r.get("message") == "Deposit Successful")
check("VULN-006 foreign account was credited", balance(OTHER_ACCOUNT) == other_before + 5000,
      "%s -> %s" % (other_before, balance(OTHER_ACCOUNT)))

b2 = balance("123456789")
r = post("deposit", account_number="123456789", amount="-4000")
check("VULN-006 negative deposit accepted", r.get("message") == "Deposit Successful")
check("VULN-006 negative deposit reverses direction", balance("123456789") == b2 - 4000,
      "%s -> %s" % (b2, balance("123456789")))

r = post("deposit", account_number="42", amount="100")
check("unknown account returns a clean error", r.get("message") == "Account does not exist")
r = post("deposit", account_number="123456789", amount="abc")
check("VULN-006 non-numeric amount accepted as 0", r.get("message") == "Deposit Successful")
r = post("deposit", password="wrong", account_number="123456789", amount="100")
check("deposit still authenticates", r.get("message") == "Wrong Credentials")

r = post("gettransactions")
types = {t["type"] for t in r["transactions"]}
check("deposits appear in transaction history", "DEPOSIT" in types, str(sorted(types)))

# ==========================================================================================
print("\n[7] Signup  -  registration, provisioning, and the validation policy")
NEW_USER = TEST_USER_PREFIX + "1"
NEW_PASSWORD = "SignUp@2026"

r = raw_post("signup", username=NEW_USER, password=NEW_PASSWORD,
             confirm_password=NEW_PASSWORD, first_name="Ray", last_name="Tester",
             email="ray.tester@example.invalid", phone="+1-555-0199",
             address="9 Test Row, Sample City")
check("POST /signup creates the account", r.get("message") == "User created successfully",
      r.get("message"))
check("signup returns a from account", len(str(r.get("from"))) == 9, r.get("from"))
check("signup returns a to account", len(str(r.get("to"))) == 9, r.get("to"))
check("the two provisioned numbers differ", r.get("from") != r.get("to"))
check("the password is not echoed back", NEW_PASSWORD not in json.dumps(r), json.dumps(r))

new_from = r.get("from")
new_to = r.get("to")

rows = accounts_of(NEW_USER)
check("exactly two accounts exist for the new user", len(rows) == 2, str(rows))
check("one from and one to account",
      sorted(t for _, t, _ in rows) == ["from", "to"], str(rows))
check("the returned numbers are the persisted ones",
      {str(n) for n, _, _ in rows} == {str(new_from), str(new_to)}, str(rows))
check("both accounts are pre-funded", all(b == r.get("opening_balance") for _, _, b in rows),
      "balance=%s" % r.get("opening_balance"))

r = post("login", username=NEW_USER, password=NEW_PASSWORD)
check("the new user can log in", r.get("message") == "Correct Credentials", r.get("message"))
r = post("getaccountdetails", username=NEW_USER, password=NEW_PASSWORD)
check("the new user owns both accounts", len(r.get("accounts", [])) == 2,
      str(len(r.get("accounts", []))))
r = post("getprofile", username=NEW_USER, password=NEW_PASSWORD)
check("the new user's profile is readable", r.get("full_name") == "Ray Tester",
      r.get("full_name"))
r = post("deposit", username=NEW_USER, password=NEW_PASSWORD,
         account_number=str(new_from), amount="250")
check("the new user can use the features", r.get("message") == "Deposit Successful",
      "balance=%s" % r.get("balance"))

r = post("getaccountdetails", username=NEW_USER, password="wrong")
check("the new account is password protected", r.get("message") == "Wrong Credentials",
      r.get("message"))

# --- the validation policy: every one of these must be refused, cleanly ---
REJECT = [
    ("duplicate username", dict(username=NEW_USER, password=NEW_PASSWORD),
     "Username already exists"),
    ("reserved backdoor name", dict(username="devadmin", password=NEW_PASSWORD),
     "That username is reserved"),
    ("reserved name, other case", dict(username="DevAdmin", password=NEW_PASSWORD),
     "That username is reserved"),
    ("missing username", dict(password=NEW_PASSWORD), "Username is required"),
    ("blank username", dict(username="   ", password=NEW_PASSWORD), "Username is required"),
    ("username too short", dict(username="ab", password=NEW_PASSWORD), None),
    ("username too long", dict(username="a" * 51, password=NEW_PASSWORD),
     "Username must be at most 50 characters"),
    ("username bad charset", dict(username="ray tester!", password=NEW_PASSWORD), None),
    ("missing password", dict(username=TEST_USER_PREFIX + "2"), "Password is required"),
    ("password too short", dict(username=TEST_USER_PREFIX + "2", password="abc12"),
     "Password must be at least 6 characters"),
    ("password too long", dict(username=TEST_USER_PREFIX + "2", password="a" * 51),
     "Password must be at most 50 characters"),
    ("password equals username", dict(username=TEST_USER_PREFIX + "2",
                                      password=TEST_USER_PREFIX + "2"),
     "Password must be different from the username"),
    ("confirmation mismatch", dict(username=TEST_USER_PREFIX + "2", password=NEW_PASSWORD,
                                   confirm_password="something-else"),
     "Passwords do not match"),
    ("invalid email", dict(username=TEST_USER_PREFIX + "2", password=NEW_PASSWORD,
                           email="not-an-email"), "Email address is not valid"),
    ("over-long first name", dict(username=TEST_USER_PREFIX + "2", password=NEW_PASSWORD,
                                  first_name="a" * 51),
     "First name must be at most 50 characters"),
    ("over-long address", dict(username=TEST_USER_PREFIX + "2", password=NEW_PASSWORD,
                               address="a" * 201),
     "Address must be at most 200 characters"),
]

#  Exactly at the minimum length must be accepted, so this boundary case is a positive one
#  and deliberately lives outside the rejection table above.
res = raw_post("signup", username=TEST_USER_PREFIX + "2b", password="abc123")
check("signup accepts a password at the minimum length",
      res.get("message") == "User created successfully", res.get("message"))

for label, fields, expected in REJECT:
    res = raw_post("signup", **fields)
    ok = res.get("message") != "User created successfully"
    if expected is not None:
        ok = ok and res.get("message") == expected
    check("signup rejects %s" % label, ok, res.get("message"))

check("no user row leaked from a rejected signup",
      accounts_of(TEST_USER_PREFIX + "2") == [],
      str(accounts_of(TEST_USER_PREFIX + "2")))
r = raw_post("signup", username=TEST_USER_PREFIX + "3", password=NEW_PASSWORD,
             email="  ", first_name="  ")
check("signup accepts the minimum viable form", r.get("message") == "User created successfully",
      r.get("message"))
r = post("getprofile", username=TEST_USER_PREFIX + "3", password=NEW_PASSWORD)
check("optional fields are stored empty, not NULL-as-text",
      r.get("email") == "" and r.get("first_name") == "", repr((r.get("email"), r.get("first_name"))))

# ==========================================================================================
print("\n[8] every endpoint rejects wrong credentials")
for ep in ("getaccountdetails", "getmyaccounts", "gettransactions", "getbeneficiaries",
           "getbillcategories", "getbillhistory", "getprofile", "addbeneficiary",
           "deletebeneficiary", "paybill", "updateprofile", "deposit"):
    r = post(ep, password="definitely-wrong")
    check("%-20s rejects bad creds" % ep, r.get("message") == "Wrong Credentials", r.get("message"))

reset_backend()
print("\n[9] fixture reset - balances back to the seeded values")
check("123456789", balance("123456789") == 99999, str(balance("123456789")))
check("555555555", balance("555555555") == 100459, str(balance("555555555")))
check("the signups made by this run are gone",
      accounts_of(NEW_USER) == [] and accounts_of(TEST_USER_PREFIX + "3") == [],
      "leftovers=%s" % (accounts_of(NEW_USER) + accounts_of(TEST_USER_PREFIX + "3")))

print("\n" + "=" * 78)
print("  %d passed, %d failed" % (passed, failed))
print("=" * 78)
sys.exit(1 if failed else 0)
