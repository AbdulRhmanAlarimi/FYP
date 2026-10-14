# Intentional Vulnerabilities — InsecureBankv2 (IntelliRASP FYP build)

> **This build is an intentionally vulnerable research target.**
> Everything listed below exists on purpose so that a RASP/ML anomaly detector can be
> trained and evaluated on it. None of it exists in any real banking application.
>
> Rule for this repository: **do not "fix" anything in this document, and do not add
> findings that are not listed here.** The pre-existing InsecureBankv2 flaws (plaintext
> HTTP, hardcoded AES key, exported components, the `devadmin` backdoor, the SMS broadcast,
> the world readable `TrackUserContentProvider`, …) are left exactly as the original
> authors shipped them.

---

## Summary table

| ID | Feature | Type (CWE) | Component | Where it lives |
|----|---------|------------|-----------|----------------|
| RASP-VULN-001 | 1. Account Details | CWE-532 / CWE-215 — sensitive data in logs | `AccountDetailsActivity.logAccountDetails()` | Android client |
| RASP-VULN-002 | 2. Transaction History | CWE-89 — SQL injection (local SQLite) | `TransactionCacheDb.search()` | Android client |
| RASP-VULN-003 | 3. Beneficiary Management | CWE-926 / CWE-862 — exported unprotected component | `BeneficiaryActivity` + manifest entry | Android client |
| RASP-VULN-004 | 4. Bill Payment | CWE-20 — improper input validation | `BillPaymentActivity.doPayBill()` and `app.py::paybill()` | Client + server |
| RASP-VULN-005 | 5. Profile Management | CWE-312 / CWE-276 — cleartext storage + wrong permissions | `ProfileActivity.dumpProfileToLocalStorage()` | Android client |
| RASP-VULN-006 | 6. Deposit Money | CWE-862 / CWE-20 — missing authorization, business logic | `DepositActivity.doDeposit()` and `app.py::deposit()` | Client + server |

Each finding is also documented **in the source**, immediately above the offending code,
so it survives a checkout of a single file. Search for `RASP-VULN-00` in:

```
InsecureBankv2/app/src/main/AndroidManifest.xml
InsecureBankv2/app/src/main/java/com/android/insecurebankv2/AccountDetailsActivity.java
InsecureBankv2/app/src/main/java/com/android/insecurebankv2/TransactionCacheDb.java
InsecureBankv2/app/src/main/java/com/android/insecurebankv2/BeneficiaryActivity.java
InsecureBankv2/app/src/main/java/com/android/insecurebankv2/BillPaymentActivity.java
InsecureBankv2/app/src/main/java/com/android/insecurebankv2/ProfileActivity.java
InsecureBankv2/app/src/main/java/com/android/insecurebankv2/DepositActivity.java
AndroLabServer/app.py
```

---

## RASP-VULN-001 — Sensitive account data written to the system log

| | |
|---|---|
| **Feature** | 1. Account Details |
| **Type** | CWE-532 Insertion of Sensitive Information into Log File (also CWE-215) |
| **Vulnerable component** | `AccountDetailsActivity.logAccountDetails()`, tag `InsecureBankAccount` |
| **Normal behaviour** | `LOGIN → ACCOUNT DETAILS → LOGOUT`. The screen shows account number, holder name, balance and account type, refreshed from `POST /getaccountdetails`, which authenticates the caller and returns only rows owned by that user. The refresh works perfectly and nothing is ever written to logcat. |
| **Attack behaviour** | Not a different input path — the leak happens on *every* normal refresh. Everything the screen displays is additionally printed to logcat, where it is readable by `adb logcat`, by any app with `READ_LOGS` (pre-Android 4.1) and by any crash/bug-report pipeline. |
| **Runtime events** | `ACCOUNT_VIEW` (success) and `BALANCE_VIEW` (success) are emitted immediately **before** each dump. The event payload deliberately does **not** contain the account data, so the anomaly is not visible in the event stream itself — it is only visible to a detector that hooks the logging sink. |
| **Reproduce** | 1. Log in.<br>2. Open **Account Details**.<br>3. `adb logcat -s InsecureBankAccount:I`<br>   → `ACCOUNT DETAILS :: holder=dinesh shetty account_number=123456789 account_type=from balance=100399 currency=USD \| account=123456789  \|  from  \|  100399 USD …` |
| **Blast radius** | Disclosure only. No state is changed, the backend is not involved, the screen keeps working. |

---

## RASP-VULN-002 — SQL injection in transaction search (local SQLite)

| | |
|---|---|
| **Feature** | 2. Transaction History |
| **Type** | CWE-89 SQL Injection, *local / on-device* variant |
| **Vulnerable component** | `TransactionCacheDb.search()` — the only unparameterised statement in the project |
| **Normal behaviour** | `LOGIN → TRANSACTION HISTORY → SYNC → FILTER → VIEW TRANSACTION`. `Show All` uses `queryRecent()`, which binds every value. The search box accepts any ordinary word ("deposit", a reference, an account number) and filters the cache correctly. |
| **Attack behaviour** | The keyword is pasted into the SQL statement with `+` concatenation, so it can inject predicates. A keyword such as `' OR '1'='1` returns every cached row although no row contains that text; a `UNION SELECT` arm runs arbitrary read-only SQL against the cache. |
| **Runtime events** | `TRANSACTION_SEARCH` (success) with `detail` containing `keyword=[…]`, followed by `TRANSACTION_SEARCH_RESULT` with `rows=<n>`. A benign search always yields `rows ≤` the number of rows actually containing the keyword; a tautology payload yields the full table. A malformed payload additionally produces `CLIENT_ERROR` with `search rejected: …` and the app stays alive. |
| **Reproduce** | 1. Log in, open **Transaction History**, press **Sync**.<br>2. Type `'  OR  '1'='1` into the search box, press **Search** → every row is returned.<br>3. Type `x') UNION SELECT reference,account_number,type,direction,amount,counterparty,txn_date FROM transaction_cache --` → the UNION arm is executed by the local SQLite engine (the payload first has to close the `( ... )` group that the LIKE block sits in).<br>4. To script it from adb, note that `input text` drops the `'` character — send each apostrophe with `input keyevent 75`. See `docs/DATASETS.md` §A2. The `preset_keyword` intent extra only applies to an in-app launch; this activity is not exported, so `am start` on it is refused. |
| **Blast radius** | The statement only ever runs against `insecurebank_cache.db`, a throw-away local cache owned by this app. It cannot reach the backend, cannot touch `mydb.db` (the `TrackUserContentProvider` database) and cannot execute code. Read-only payloads only. |

---

## RASP-VULN-003 — Exported, unprotected beneficiary component

| | |
|---|---|
| **Feature** | 3. Beneficiary Management |
| **Type** | CWE-926 Improper Export of Android Application Components + CWE-862 Missing Authorization |
| **Vulnerable component** | `BeneficiaryActivity`, declared with `android:exported="true"` and an `<intent-filter>` and **no** `android:permission`; plus `BeneficiaryActivity.handleExternalAutofill()` |
| **Normal behaviour** | `LOGIN → BENEFICIARIES → ADD BENEFICIARY → TRANSFER`. The screen is opened from the `PostLogin` hub, a beneficiary is added through the form, the row shows up in the list, and `Pick Beneficiary` on the transfer screen fills the "To Account" field. |
| **Attack behaviour** | The activity is reachable by any app on the device and by `adb shell am start`. It performs its privileged action purely on the strength of the extras it is handed — the target account and the pre-filled beneficiary — with no permission check, no caller verification and no user confirmation. An external app can therefore register a payee of its choosing in the victim's beneficiary list without the victim ever seeing the screen, and it can read the existing payee names and account numbers by simply opening the activity. |
| **Runtime events** | `BENEFICIARY_ADD` with `detail` containing **`source=external_intent`**, preceded by `BENEFICIARY_VIEW` and the usual `SERVER_REQUEST` / `SERVER_RESPONSE` pair. The success flag is identical to an in-app add, which is exactly what makes the cross-app action detectable. |
| **Reproduce** | While `dinesh` is logged in:<br>`adb shell am start -n com.android.insecurebankv2/.BeneficiaryActivity --es uname dinesh --es autofill_bene_name "External Payee" --es autofill_bene_account 111122223333`<br>→ `External Payee` appears in dinesh's beneficiary list, the UI is never shown, no permission was required.<br>Without the autofill extras the same command still discloses every payee name and account number. |
| **Blast radius** | Limited to the beneficiary list of the account already logged in on the device. Nothing is deleted, no money moves, and the normal in-app workflow is untouched because the trigger exists only in the intent extras. |

---

## RASP-VULN-004 — Improper input validation in bill payment

| | |
|---|---|
| **Feature** | 4. Bill Payment |
| **Type** | CWE-20 Improper Input Validation |
| **Vulnerable component** | `BillPaymentActivity.doPayBill()` (client, no validation before sending) and `AndroLabServer/app.py::paybill()` (server, no validation either) |
| **Normal behaviour** | `LOGIN → BILL PAYMENT → ENTER DETAILS → CONFIRM → SUCCESS`. A real category, a 6–20 digit bill number and a positive amount produce a successful payment that appears in the payment history and writes a `BILL_PAYMENT` row into the transaction history. |
| **Attack behaviour** | No check of any kind is performed on either side. `bill_number` may be empty, hundreds of characters long, or contain SQL/shell metacharacters; `amount` may be negative, decimal, empty or non-numeric. The request is sent anyway and the server answers `Bill Payment Successful`, so a malformed payment is stored and displayed as a legitimate one. |
| **Runtime events** | `BILL_PAYMENT` `stage=submit` then `stage=result`, both carrying `amount="<raw text>"`, `amount_numeric=<bool>` and `bill_len=<n>` in the `detail`. The signature of the attack is `amount_numeric=false` or a negative `amount` combined with `result=success`; that combination never occurs in a benign workflow. |
| **Reproduce** | Log in → **Bill Payment**, then either<br>(a) type `'  OR  1=1--` into "Bill / consumer number", `1000` into the amount, press **Pay Bill**; or<br>(b) type `-1` into the amount and press **Pay Bill**.<br>In both cases the screen reports success and the row shows up in the payment history.<br>Server-side equivalent:<br>`curl -d "username=dinesh&password=Dinesh@123\$&category=Water&bill_number=' OR 1=1--&amount=-1&payer_account=123456789" http://<host>:8888/paybill` |
| **Blast radius** | The value is only ever bound as a parameter of an `INSERT` on the server — never concatenated into SQL, never passed to a shell — so it cannot execute code and cannot destroy data. A non-positive amount does not move any balance, so the fixture stays consistent. |

---

## RASP-VULN-005 — Profile exposed in cleartext local storage and logs

| | |
|---|---|
| **Feature** | 5. Profile Management |
| **Type** | CWE-312 Cleartext Storage of Sensitive Information + CWE-276 Incorrect Default Permissions + CWE-532 (log copy) |
| **Vulnerable component** | `ProfileActivity.dumpProfileToLocalStorage()` |
| **Normal behaviour** | `LOGIN → PROFILE → EDIT PROFILE → SAVE`. The screen loads name, e-mail, phone and address from `POST /getprofile`, the fields are editable and saving persists the change through `POST /updateprofile`. |
| **Attack behaviour** | Every successful profile view **and** every save additionally copies the whole profile in clear text to (a) `/sdcard/InsecureBankProfiles/Profile_<user>.txt`, which is world readable by every application and by any adb session, (b) a `MODE_WORLD_READABLE` `SharedPreferences` file, and (c) the system log under the tag `InsecureBankProfile`. Any other app on the device, or anyone with the phone over adb, can read the profile without ever logging in. |
| **Runtime events** | `PROFILE_VIEW` / `PROFILE_UPDATE` (result=success) are emitted just before each dump. The event payload itself never carries the profile, so the leak is not visible in the event stream. |
| **Reproduce** | 1. Log in → **Profile** → **Refresh**.<br>2. `adb shell cat /sdcard/InsecureBankProfiles/Profile_dinesh.txt`<br>   or `adb logcat -s InsecureBankProfile:I`<br>   → `PROFILE username=dinesh full_name=dinesh shetty email=dinesh.test@example.invalid phone=+1-555-0100 address=12 Test Street, Sample City captured=…` |
| **Blast radius** | The stored values are the fake seeded test contacts (`SEED_CONTACTS` in `AndroLabServer/app.py`) — no real person is involved. Nothing is transmitted anywhere. The dump is best effort: if the filesystem is unavailable the app keeps working normally. |

---

## RASP-VULN-006 — Deposit: missing authorization and business-logic weakness

| | |
|---|---|
| **Feature** | 6. Deposit Money |
| **Type** | CWE-862 Missing Authorization + CWE-20 Improper Input Validation (business logic) |
| **Vulnerable component** | `DepositActivity.doDeposit()` (client builds the request) and `AndroLabServer/app.py::deposit()` (server accepts it) |
| **Normal behaviour** | `LOGIN → DEPOSIT → ACCOUNT → AMOUNT → CONFIRM → BALANCE UPDATED`. Picking one of the caller's own accounts and a positive amount credits it, writes a `DEPOSIT` row into the transaction history and shows the new balance. |
| **Attack behaviour** | The screen offers an "Or enter another account number" field, and the server **never** compares the owner of the target account with the authenticated caller, so any account in the fixture can be credited by any logged-in customer. The amount is additionally accepted with a negative sign, which reverses the direction of the movement. |
| **Runtime events** | `DEPOSIT` `stage=submit` then `stage=result`, both carrying `account=<n>`, **`foreign_account=<bool>`**, `amount="<raw>"`, `amount_numeric=<bool>`, `negative=<bool>` and the resulting `balance`. The signature of the attack is `foreign_account=true` together with `result=success`, or `negative=true`; neither ever occurs in a benign workflow. |
| **Reproduce** | Log in as `dinesh` → **Deposit Money**, then<br>(a) type `555555555` (jack's account) into "Or enter another account number" and `5000` into the amount, press **Confirm Deposit** → jack's balance grows by 5000 while the event says `foreign_account=true, result=success`; or<br>(b) type `-1` into the amount and press **Confirm Deposit**.<br>Server-side equivalent:<br>`curl -d "username=dinesh&password=Dinesh@123\$&account_number=555555555&amount=5000" http://<host>:8888/deposit` |
| **Blast radius** | Confined to the local research fixture `AndroLabServer/mydb.db`. An unknown account number still returns a clean error, the balance is never left undefined, and the application keeps working normally. |

---

## What was deliberately *not* done

* The original vulnerabilities of InsecureBankv2 were **not** touched, so the pre-existing
  attack walkthroughs in `Walkthroughs/` still work.
* No new feature is vulnerable other than the six above. In particular
  `/getaccountdetails`, `/gettransactions`, `/getbeneficiaries`, `/addbeneficiary`,
  `/deletebeneficiary`, `/getbillcategories`, `/getbillhistory`, `/getprofile`,
  `/updateprofile` and `/getmyaccounts` all authenticate the caller, and
  `/deletebeneficiary` additionally verifies ownership of the row it deletes.
* No payload used by any of the six findings executes code, spawns a shell, deletes data
  or contacts a third party. All of them are contained inside this local fixture.
* No attack trigger fires during a normal workflow. Each one needs a deliberate,
  documented action (a crafted intent, a crafted keyword, a malformed field value).

## Signup — deliberately *not* a seventh finding

`/signup` (`AndroLabServer/app.py::signup` + `validate_signup`) and `SignUpActivity` are
the one part of this build that is intentionally well behaved. It implements the
"Create User" stub that the original `LoginActivity.createUser()` left as a
Work-In-Progress toast, and it **must not** be turned into a finding: the six-row summary
table at the top of this document is the complete list.

The policy is enforced on the device for immediate feedback and re-checked by the server,
which is the authority:

| Rule | Server message on refusal |
|------|----------------------------|
| username present, 3–50 chars, `[A-Za-z0-9._-]` | `Username is required` / `Username must be 3-50 characters …` |
| every value fits the width of its `users` column in `models.py` | `… must be at most N characters` |
| username not already taken (the `UNIQUE` constraint is the authority, so a race is a clean duplicate, not a 500) | `Username already exists` |
| `devadmin` is reserved — it is answered unconditionally by `/devlogin`, so a row with that name would be handed the pre-existing backdoor | `That username is reserved` |
| password present, 6–50 chars, different from the username | `Password is required` / `Password must be at least 6 characters` / `Password must be different from the username` |
| `confirm_password` matches when the field is supplied | `Passwords do not match` |
| e-mail, when given, is well formed | `Email address is not valid` |

A successful signup creates the `users` row and allocates one pre-funded `from` and one
`to` account, so the new customer can use all six features after the first login. The
plaintext password is stored exactly the way `/login` and `/changepassword` already store
it — that is a **pre-existing** property of this application, not something signup adds,
and it is recorded here only so that nobody "discovers" it as a new finding later.

`tools/verify_features.py` §7 asserts the whole policy, including the boundary cases, and
removes the accounts it creates again (`rasptest*`).
