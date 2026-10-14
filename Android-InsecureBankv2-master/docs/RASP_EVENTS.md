# IntelliRASP Event Catalogue

Every screen reports to a single sink: `RaspEvent`
(`InsecureBankv2/app/src/main/java/com/android/insecurebankv2/RaspEvent.java`).

## Where the stream goes

| Sink | Path | How to read it |
|------|------|----------------|
| logcat | tag `InsecureRASP` | `adb logcat -s InsecureRASP:I` |
| JSONL file | `/sdcard/Android/data/com.android.insecurebankv2/files/rasp_events.jsonl` | `adb pull` |
| internal fallback | `/data/data/com.android.insecurebankv2/files/rasp_events.jsonl` | `adb shell run-as com.android.insecurebankv2 cat files/rasp_events.jsonl` |

One line per event, one JSON object per line. Written by a single background thread in
call order, so within one process the file is sequence-sorted.

`seq` is a **per-process** counter, and the JSONL file is append-only and survives an app
restart. If the process is killed and relaunched (a crash, a force-stop, an emulator
reboot) the counter restarts from 1 while the file keeps growing, so `seq` alone is not
globally monotonic across a file. Order the dataset with **`ts_ms`** (or `ts`) and use
`seq` only to order events *within* a single `session` between restarts. A new
`session` UUID is minted at every `LOGIN_SUCCESS`, and process restarts without a
login reuse the previous session id, so `session` + `ts_ms` is the stable grouping key.

## Record schema

```json
{
  "ts":      "2026-09-29T07:12:41.882Z",   // ISO-8601 UTC
  "ts_ms":   1788001961882,               // epoch millis
  "seq":     42,                          // per-process monotonic counter
  "session": "b3f1…",                     // new UUID at every LOGIN_SUCCESS
  "event":   "DEPOSIT",
  "component":"DepositActivity",          // emitting screen
  "user":    "dinesh",                    // username only
  "result":  "success",                   // success | failure
  "op_id":   "op17",                      // correlates the calls of one user action
  "detail":  "account=123456789 foreign_account=false amount=\"500\" …"
}
```

### Data handling rules

* Passwords, authentication tokens, OTP codes, card numbers and session cookies are
  **never** passed to `RaspEvent`.
* `RaspEvent.registerSecret()` installs the plaintext session password as a scrub string
  after every login, so even an accidental copy into a `detail` value is masked to `***`.
* `detail` is clamped to 220 characters and newlines are flattened, so one event is always
  one log line (logcat's 4 KB limit is never hit).
* The *fields* carrying a value are the only thing that varies: e.g. a bill payment records
  the raw amount text but never the biller's account credentials.

## Event names

### Lifecycle

| Event | Emitted by | `result` | Notes |
|-------|-----------|----------|-------|
| `APP_START` | `LoginActivity.onCreate` | success | first event of every process, carries `pid` |
| `LOGIN_SUCCESS` | `DoLogin` | success | `detail` has `backdoor=true` for the `devadmin` account |
| `LOGIN_FAILURE` | `DoLogin` | failure | `detail` has the server's message |
| `LOGOUT` | every screen's menu *Restart* and the `PostLogin` *Logout* button | success | clears the local session |
| `SESSION_EXPIRED` | any new screen | failure | no local session, user bounced to login |
| `NAVIGATE` | every screen | success | `detail` = `to=<TargetActivity>` |
| `CLIENT_ERROR` | any screen | failure | parse / transport / local-DB error |

### Signup

`SignUpActivity` runs **before** authentication, so it is the only screen that reports
without a `user` of its own. The `user` field carries the username being registered — at
that point in the flow that is data the user is inventing, not data that was disclosed.
No signup event mints a `session`; the first real session begins at the `LOGIN_SUCCESS`
that follows it.

| Event | When | `result` | Notes |
|-------|------|----------|-------|
| `SIGNUP_ATTEMPT` | the form passed the on-device policy and is about to be sent | success | `username_len`, `password_len`, `password_confirmed`, `has_email` |
| `SIGNUP_SUCCESS` | `POST /signup` returned `User created successfully` | success | `stage=server accounts_provisioned=2` |
| `SIGNUP_FAILURE` | the form was refused, on device or by the server | failure | `stage=client|server`, `reason=policy\|rejected\|transport`, and the server's own message for `stage=server` |

The password is never part of a `detail`; only its length and the result of the
confirmation comparison are recorded, exactly like `PASSWORD_CHANGE`.

**Signup is not one of the six findings.** It is the one screen of this build that is
deliberately well behaved, so a `SIGNUP_FAILURE` is a normal outcome of a normal trace and
must stay labelled benign. See `INTENTIONAL_VULNERABILITIES.md`.

### 1. Account Details

| Event | When |
|-------|------|
| `ACCOUNT_VIEW` | the screen was opened and the account list was parsed |
| `ACCOUNT_REFRESH` | the user pressed **Refresh** |
| `BALANCE_VIEW` | a balance was rendered (also used by Deposit) |

`detail` e.g. `accounts=3 balance=100399`. The account number and the holder name are
**not** in the event — they leak through the log instead (RASP-VULN-001).

### 2. Transaction History

| Event | When |
|-------|------|
| `TRANSACTION_HISTORY_VIEW` | screen opened, **Show All** pressed or **Sync** completed (`action=sync|show_all|open_row`) |
| `TRANSACTION_SEARCH` | the user pressed **Search**; `keyword_len`, `keyword=[…]`, `type` |
| `TRANSACTION_SEARCH_RESULT` | the search returned; `rows=<n>` |

### 3. Beneficiary Management

| Event | When |
|-------|------|
| `BENEFICIARY_VIEW` | the list was loaded; `rows=<n> select_mode=<bool>` |
| `BENEFICIARY_ADD` | add attempted; `source=form|external_intent`, `account`, `type` |
| `BENEFICIARY_DELETE` | delete attempted; `id=<n>` |
| `BENEFICIARY_SELECT` | a payee was picked in picker mode or applied by the transfer screen |

### 4. Bill Payment

| Event | When |
|-------|------|
| `BILL_PAYMENT` | `stage=submit` before the request, `stage=result` after it; carries `category`, `account`, `bill_len`, `amount`, `amount_numeric`, `reference` |
| `BILL_PAYMENT_HISTORY_VIEW` | the history list was refreshed; `rows=<n>` |

### 5. Profile Management

| Event | When |
|-------|------|
| `PROFILE_VIEW` | the profile was loaded; `fields=6 source=server` |
| `PROFILE_UPDATE` | **Save Profile** was pressed; `fields_changed=<n>` |
| `PASSWORD_CHANGE` | from the pre-existing `ChangePassword` screen; `strength_policy=passed\|rejected`. The new password is never part of the event. |

### 6. Deposit Money

| Event | When |
|-------|------|
| `DEPOSIT` | `stage=submit` before the request, `stage=result` after it; carries `account`, `foreign_account`, `amount`, `amount_numeric`, `negative`, `balance` |
| `BALANCE_VIEW` | accounts were loaded or a new balance was returned |

### Pre-existing features (instrumented, not modified)

| Event | When |
|-------|------|
| `TRANSFER` | the transfer screen finished a request; `from`, `to`, `amount` |
| `BENEFICIARY_SELECT` | `Pick Beneficiary` on the transfer screen returned a value |

### Infrastructure

| Event | When |
|-------|------|
| `SERVER_REQUEST` | one HTTP POST is about to be sent; `detail` = endpoint |
| `SERVER_RESPONSE` | the response arrived; `detail` = `endpoint bytes=<n>` |

## Features recommended to the ML model

| Feature | Source |
|---------|--------|
| `event` (categorical) | `event` |
| `component` (categorical) | `component` |
| `result` (binary) | `result` |
| elapsed time since previous event, per component | `ts_ms` + `seq` |
| time since `LOGIN_SUCCESS` | `ts_ms` joined on `session` |
| count of each event type in the session | `seq` window |
| count of `NAVIGATE` hops in the session | `seq` window |
| number of distinct components visited | `seq` window |
| keyword length / non-alphanumeric ratio on `TRANSACTION_SEARCH` | `detail` |
| `amount_numeric`, `negative`, `bill_len` on `BILL_PAYMENT` | `detail` |
| `foreign_account`, `negative` on `DEPOSIT` | `detail` |
| `source` on `BENEFICIARY_ADD` | `detail` |
| number of failures in the session | `result == failure` |
| elapsed time of the network round trips | `SERVER_REQUEST` → `SERVER_RESPONSE` on `op_id` |
